# Copyright (c) 2003-2012 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino (beto@coresecurity.com)
#
# Description:
#   [MS-SMB2] Protocol Implementation (SMB2 and SMB3)
#   As you might see in the code, it's implemented strictly following 
#   the structures defined in the protocol specification. This may
#   not be the most efficient way (e.g. self._Connection is the
#   same to self._Session in the context of this library ) but
#   it certainly helps following the document way easier.
#
# ToDo: 
# [ ] Implement SMB2_CHANGE_NOTIFY
# [ ] Implement SMB2_QUERY_INFO
# [ ] Implement SMB2_SET_INFO
# [ ] Implement SMB2_OPLOCK_BREAK
# [ ] Implement SMB3 signing and encryption
# [ ] Add more backward compatible commands from the smb.py code
# [ ] Fix up all the 'ToDo' comments inside the code
#

from impacket import nmb, smb3structs, nt_errors, spnego, ntlm, uuid
from smb3structs import *
from nt_errors import *
from spnego import *
from binascii import a2b_hex
import socket, string, ntpath
# For signing
import hashlib, hmac, copy

# Structs to be used
TREE_CONNECT = {
    'ShareName'       : '',
    'TreeConnectId'   : 0,
    'Session'         : 0,
    'IsDfsShare'      : False,
    # If the client implements the SMB 3.0 dialect, 
    # the client MUST also implement the following
    'IsCAShare'       : False,
    'EncryptData'     : False,
    'IsScaleoutShare' : False,
    # Outside the protocol
    'NumberOfUses'    : 0,
}

FILE = {
    'OpenTable'       : [],
    'LeaseKey'        : '',
    'LeaseState'      : 0,
    'LeaseEpoch'      : 0,
}

OPEN = {
    'FileID'             : '',
    'TreeConnect'        : 0,
    'Connection'         : 0, # Not Used
    'Oplocklevel'        : 0,
    'Durable'            : False,
    'FileName'           : '',
    'ResilientHandle'    : False,
    'LastDisconnectTime' : 0,
    'ResilientTimeout'   : 0,
    'OperationBuckets'   : [],
    # If the client implements the SMB 3.0 dialect, 
    # the client MUST implement the following
    'CreateGuid'         : '',
    'IsPersistent'       : False,
    'DesiredAccess'      : '',
    'ShareMode'          : 0,
    'CreateOption'       : '',
    'FileAttributes'     : '',
    'CreateDisposition'  : '',
}

REQUEST = {
    'CancelID'     : '',
    'Message'      : '',
    'Timestamp'    : 0,
}

CHANNEL = {
    'SigningKey' : '',
    'Connection' : 0,
}


class SessionError(Exception):
    def __init__( self, error = 0, packet=0):
        Exception.__init__(self)
        self.error = error
        self.packet = packet
       
    def get_error_code( self ):
        return self.error

    def get_error_packet( self ):
        return self.packet

    def __str__( self ):
        return 'SMB SessionError: %s(%s)' % (ERROR_MESSAGES[self.error])


class SMB3:
    def __init__(self, remote_name, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = 445, timeout=10, UDP = 0):

        # [MS-SMB2] Section 3
        self.RequireMessageSigning = False    #
        self.ConnectionTable = {}
        self.GlobalFileTable = {}
        self.ClientGuid = ''                  #
        # Only for SMB 3.0
        self.EncryptionAlgorithmList = ['AES-CCM']
        self.MaxDialect = []
        self.RequireSecureNegotiate = False

        # Per Transport Connection Data
        self._Connection = {
            # Indexed by SessionID
            #'SessionTable'             : {},    
            # Indexed by MessageID
            'OutstandingRequests'      : {},
            'OutstandingResponses'     : {},    #
            'SequenceWindow'           : 0,     #
            'GSSNegotiateToken'        : '',    #
            'MaxTransactSize'          : 0,     #
            'MaxReadSize'              : 0,     #
            'MaxWriteSize'             : 0,     #
            'ServerGuid'               : '',    #
            'RequireSigning'           : False, #
            'ServerName'               : '',    #
            # If the client implements the SMB 2.1 or SMB 3.0 dialects, it MUST 
            # also implement the following
            'Dialect'                  : '',    #
            'SupportsFileLeasing'      : False, #
            'SupportsMultiCredit'      : False, #
            # If the client implements the SMB 3.0 dialect, 
            # it MUST also implement the following
            'SupportsDirectoryLeasing' : False, #
            'SupportsMultiChannel'     : False, #
            'SupportsPersistentHandles': False, #
            'SupportsEncryption'       : False, #
            'ClientCapabilities'       : 0,
            'ServerCapabilities'       : 0,    #
            'ClientSecurityMode'       : 0,    #
            'ServerSecurityMode'       : 0,    #
            # Outside the protocol
            'ServerIP'                 : '',    #
        }
   
        self._Session = {
            'SessionID'                : 0,   #
            'TreeConnectTable'         : {},    #
            'SessionKey'               : '',    #
            'SigningRequired'          : False, #
            'Connection'               : 0,     # 
            'UserCredentials'          : '',    #
            'OpenTable'                : {},    #
            # If the client implements the SMB 3.0 dialect, 
            # it MUST also implement the following
            'ChannelList'              : [],
            'ChannelSequence'          : 0,
            'EncryptData'              : False,
            'EncryptionKey'            : '',
            'DecryptionKey'            : '',
            'SigningKey'               : '',  
            'ApplicationKey'           : '',
            # Outside the protocol
            'SessionFlags'             : 0,     # 
            'ServerName'               : '',    #
            'ServerDomain'             : '',    #
            'ServerOS'                 : '',    #
        }

        self.SMB_PACKET = SMB2Packet
        
        self._timeout = timeout
        self._Connection['ServerIP'] = remote_host
        
        if not my_name:
            my_name = socket.gethostname()
            i = string.find(my_name, '.')
            if i > -1:
                my_name = my_name[:i]

        if sess_port == 445 and remote_name == '*SMBSERVER':
           self._Connection['ServerName'] = remote_host
        else:
           self._Connection['ServerName'] = remote_name

        if UDP:
            self._NetBIOSSession = nmb.NetBIOSUDPSession(my_name, self._Connection['ServerName'], remote_host, host_type, sess_port, self._timeout)
        else:
            self._NetBIOSSession = nmb.NetBIOSTCPSession(my_name, self._Connection['ServerName'], remote_host, host_type, sess_port, self._timeout)

            self.negotiateSession()

    def printStatus(self):
        print "CONNECTION"
        for i in self._Connection.items():
            print "%-40s : %s" % i
        print
        print "SESSION"
        for i in self._Session.items():
            print "%-40s : %s" % i

    def getServerName(self):
        return self._Session['ServerName']

    def getServerIP(self):
        return self._Connection['ServerIP']

    def getServerDomain(self):
        return self._Session['ServerDomain']

    def getServerOS(self):
        return self._Session['ServerOS']

    def isGuestSession(self):
        return self._Session['SessionFlags'] & SMB2_SESSION_FLAG_IS_GUEST 

    def setTimeout(self, timeout):
        self._timeout = timeout

    def signSMB(self, packet):
        #raise
        packet['Signature'] = '\x00'*16
        if self._Connection['Dialect'] == SMB2_DIALECT_21:
            if len(self._Session['SessionKey']) > 0:
                signature = hmac.new(self._Session['SessionKey'], str(packet), hashlib.sha256).digest()
                packet['Signature'] = signature[:16]
        else:
            print "Signing not yet Implemented for dialect %x" % self._Connection['Dialect']
      
     
    def sendSMB(self, packet):
        # The idea here is to receive multiple/single commands and create a compound request, and send it
        # Should return the MessageID for later retrieval. Implement compounded related requests.

        # If Connection.Dialect is equal to "3.000" and if Connection.SupportsMultiChannel or
        # Connection.SupportsPersistentHandles is TRUE, the client MUST set ChannelSequence in the
        # SMB2 header to Session.ChannelSequence

        # Check this is not a CANCEL request. If so, don't consume sequece numbers
        if packet['Command'] is not SMB2_CANCEL:
            packet['MessageID'] = self._Connection['SequenceWindow']
            self._Connection['SequenceWindow'] += 1
        packet['SessionID'] = self._Session['SessionID']

        # Default the credit charge to 1 unless set by the caller
        if packet.fields.has_key('CreditCharge') is False:
            packet['CreditCharge'] = 1

        # Standard credit request after negotiating protocol
        if self._Connection['SequenceWindow'] > 3:
            packet['CreditRequestResponse'] = 127

        if self._Session['SigningRequired'] is True and self._Connection['SequenceWindow'] > 3:
            if packet['TreeID'] > 0 and self._Session['TreeConnectTable'].has_key(packet['TreeID']) is True:
                if self._Session['TreeConnectTable'][packet['TreeID']]['EncryptData'] is False:
                    packet['Flags'] = SMB2_FLAGS_SIGNED
                    self.signSMB(packet)
            elif packet['TreeID'] == 0:
                packet['Flags'] = SMB2_FLAGS_SIGNED
                self.signSMB(packet)

        self._NetBIOSSession.send_packet(str(packet))
        return packet['MessageID']

    def recvSMB(self, packetID = None):
        # First, verify we don't have the packet already
        if self._Connection['OutstandingResponses'].has_key(packetID):
            return self._Connection['OutstandingResponses'].pop(packetID) 

        data = self._NetBIOSSession.recv_packet(self._timeout) 

        # In all SMB dialects for a response this field is interpreted as the Status field. 
        # This field can be set to any value. For a list of valid status codes, 
        # see [MS-ERREF] section 2.3.
        packet = SMB2Packet(data.get_trailer())

        # Loop while we receive pending requests
        if packet['Status'] == STATUS_PENDING:
            status = STATUS_PENDING
            while status == STATUS_PENDING:
                data = self._NetBIOSSession.recv_packet(self._timeout) 
                packet = SMB2Packet(data.get_trailer())
                status = packet['Status']

        if packet['MessageID'] == packetID or packetID is None:
        #    if self._Session['SigningRequired'] is True:
        #        self.signSMB(packet)
            # Let's update the sequenceWindow based on the CreditsCharged
            self._Connection['SequenceWindow'] += (packet['CreditCharge'] - 1)
            return packet
        else:
            self._Connection['OutstandingResponses'][packet['MessageID']] = packet
            return self.recvSMB(packetID) 

    def negotiateSession(self):
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_NEGOTIATE
        negSession = SMB2Negotiate()

        negSession['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED 
        if self.RequireMessageSigning is True:
            negSession['SecurityMode'] |= SMB2_NEGOTIATE_SIGNING_REQUIRED
        negSession['Capabilities'] = 0
        negSession['ClientGuid'] = self.ClientGuid
        negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
        negSession['DialectCount'] = len(negSession['Dialects'])
        packet['Data'] = negSession

        # Storing this data for later use
        self._Connection['ClientSecurityMode'] = negSession['SecurityMode']
        self._Connection['Capabilities']       = negSession['Capabilities']

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
             # ToDo this:
             # If the DialectRevision in the SMB2 NEGOTIATE Response is 0x02FF, the client MUST issue a new
             # SMB2 NEGOTIATE request as described in section 3.2.4.2.2.2 with the only exception 
             # that the client MUST allocate sequence number 1 from Connection.SequenceWindow, and MUST set
             # MessageId field of the SMB2 header to 1. Otherwise, the client MUST proceed as follows.
            negResp = SMB2Negotiate_Response(ans['Data'])
            self._Connection['MaxTransactSize']   = negResp['MaxTransactSize']
            self._Connection['MaxReadSize']       = negResp['MaxReadSize']
            self._Connection['MaxWriteSize']      = negResp['MaxWriteSize']
            self._Connection['ServerGuid']        = negResp['ServerGuid']
            self._Connection['GSSNegotiateToken'] = negResp['Buffer']
            self._Connection['Dialect']           = negResp['DialectRevision']
            if (negResp['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED) == SMB2_NEGOTIATE_SIGNING_REQUIRED:
                self._Connection['RequireSigning'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LEASING) == SMB2_GLOBAL_CAP_LEASING: 
                self._Connection['SupportsFileLeasing'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LARGE_MTU) == SMB2_GLOBAL_CAP_LARGE_MTU:
                self._Connection['SupportsMultiCredit'] = True

            if self._Connection['Dialect'] == SMB2_DIALECT_30:
                # Switching to the right packet format
                self.SMB_PACKET = SMB3Packet
                if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) == SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                    self._Connection['SupportsDirectoryLeasing'] = True
                if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_MULTI_CHANNEL) == SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                    self._Connection['SupportsMultiChannel'] = True
                if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) == SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:
                    self._Connection['SupportsPersistentHandles'] = True
                if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
                    self._Connection['SupportsEncryption'] = True

                self._Connection['ServerCapabilities'] = negResp['Capabilities']
                self._Connection['ServerSecurityMode'] = negResp['SecurityMode']

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
        # If we have hashes, normalize them
        if ( lmhash != '' or nthash != ''):
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try: # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        sessionSetup = SMB2SessionSetup()
        if self.RequireMessageSigning is True:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
        #sessionSetup['Capabilities'] = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_DFS

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit() 

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1('',domain, self._Connection['RequireSigning'])
        blob['MechToken'] = str(auth)

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()

        # ToDo:
        # If this authentication is for establishing an alternative channel for an existing Session, as specified
        # in section 3.2.4.1.7, the client MUST also set the following values:
        # The SessionId field in the SMB2 header MUST be set to the Session.SessionId for the new
        # channel being established.
        # The SMB2_SESSION_FLAG_BINDING bit MUST be set in the Flags field.
        # The PreviousSessionId field MUST be set to zero.

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            self._Session['SessionID']       = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (user, password, domain, lmhash, nthash)
            self._Session['Connection']      = self._NetBIOSSession.get_socket()
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                infoFields = ntlmChallenge['TargetInfoFields']
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']]) 
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                   try:
                       self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass 
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                   try:
                       if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'): 
                           self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                   except:
                       # For some reason, we couldn't decode Unicode here.. silently discard the operation
                       pass 

                # Parse Version to know the target Operating system name. Not provided elsewhere anymore
                if ntlmChallenge.fields.has_key('Version'):
                    version = ntlmChallenge['Version']
                    self._Session['ServerOS'] = "Windows %d.%d Build %d" % (ord(version[0]), ord(version[1]), struct.unpack('<H',version[2:4])[0])

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash)

            if exportedSessionKey is not None: 
                self._Session['SessionKey']  = exportedSessionKey

            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = str(type3)

            # Reusing the previous structure
            sessionSetup['SecurityBufferLength'] = len(respToken2)
            sessionSetup['Buffer']               = respToken2.getData()

            packetID = self.sendSMB(packet)
            packet = self.recvSMB(packetID)
            if packet.isValidAnswer(STATUS_SUCCESS):
                sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
                self._Session['SessionFlags'] = sessionSetupResponse['SessionFlags']
                return True

    def connectTree(self, share):

        # Just in case this came with the full path (maybe an SMB1 client), let's just leave 
        # the sharename, we'll take care of the rest

        #print self._Session['TreeConnectTable']
        share = share.split('\\')[-1]
        if self._Session['TreeConnectTable'].has_key(share):
            # Already connected, no need to reconnect
            treeEntry =  self._Session['TreeConnectTable'][share]
            treeEntry['NumberOfUses'] += 1
            self._Session['TreeConnectTable'][treeEntry['TreeConnectId']]['NumberOfUses'] += 1
            return treeEntry['TreeConnectId']

        #path = share
        path = '\\\\' + self._Connection['ServerName'] + '\\' +share
        treeConnect = SMB2TreeConnect()
        treeConnect['Buffer']     = path.encode('utf-16le')
        treeConnect['PathLength'] = len(path)*2
         
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_TREE_CONNECT
        packet['Data'] = treeConnect
        packetID = self.sendSMB(packet)
        packet = self.recvSMB(packetID)
        if packet.isValidAnswer(STATUS_SUCCESS):
           treeConnectResponse = SMB2TreeConnect_Response(packet['Data'])
           treeEntry = copy.deepcopy(TREE_CONNECT)
           treeEntry['ShareName']     = share
           treeEntry['TreeConnectId'] = packet['TreeID']
           treeEntry['Session']       = packet['SessionID']
           treeEntry['NumberOfUses'] += 1
           if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_DFS) == SMB2_SHARE_CAP_DFS:
               treeEntry['IsDfsShare'] = True
           if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY) == SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY:
               treeEntry['IsCAShare'] = True

           if self._Connection['Dialect'] == SMB2_DIALECT_30:
               if (self._Connection['SupportsEncryption'] is True) and ((treeConnectResponse['ShareFlags'] & SMB2_SHAREFLAG_ENCRYPT_DATA) == SMB2_SHAREFLAG_ENCRYPT_DATA):
                   treeEntry['EncryptData'] = True
                   # ToDo: This and what follows
                   # If Session.EncryptData is FALSE, the client MUST then generate an encryption key, a
                   # decryption key as specified in section 3.1.4.2, by providing the following inputs and store
                   # them in Session.EncryptionKey and Session.DecryptionKey:
               if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_SCALEOUT) == SMB2_SHARE_CAP_SCALEOUT:
                   treeEntry['IsScaleoutShare'] = True

           self._Session['TreeConnectTable'][packet['TreeID']] = treeEntry
           self._Session['TreeConnectTable'][share]            = treeEntry

           return packet['TreeID'] 

    def disconnectTree(self, treeId):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        if self._Session['TreeConnectTable'].has_key(treeId):
            # More than 1 use? descrease it and return, if not, send the packet
            if self._Session['TreeConnectTable'][treeId]['NumberOfUses'] > 1:
                treeEntry =  self._Session['TreeConnectTable'][treeId]
                treeEntry['NumberOfUses'] -= 1
                self._Session['TreeConnectTable'][treeEntry['ShareName']]['NumberOfUses'] -= 1
                return True

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_TREE_DISCONNECT
        packet['TreeID'] = treeId
        treeDisconnect = SMB2TreeDisconnect()
        packet['Data'] = treeDisconnect
        packetID = self.sendSMB(packet)
        packet = self.recvSMB(packetID)
        if packet.isValidAnswer(STATUS_SUCCESS):
            shareName = self._Session['TreeConnectTable'][treeId]['ShareName']
            del(self._Session['TreeConnectTable'][shareName])
            del(self._Session['TreeConnectTable'][treeId])
            return True

    def create(self, treeId, fileName, desiredAccess, shareMode, creationOptions, creationDisposition, fileAttributes, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        fileName = string.replace(fileName, '/', '\\')
        if self._Session['TreeConnectTable'][treeId]['IsDfsShare'] is True:
            pathName = fileName
        else:
            pathName = '\\\\' + self._Connection['ServerName'] + '\\' + fileName

        fileEntry = copy.deepcopy(FILE)
        fileEntry['LeaseKey']   = uuid.generate()
        fileEntry['LeaseState'] = SMB2_LEASE_NONE
        self.GlobalFileTable[pathName] = fileEntry 

        if self._Connection['Dialect'] == SMB2_DIALECT_30 and self._Connection['SupportsDirectoryLeasing'] is True:
           # Is this file NOT on the root directory?
           if len(fileName.split('\\')) > 2:
               parentDir = ntpath.dirname(pathName)
           if self.GlobalFileTable.has_key(parentDir):
               print "Don't know what to do now! :-o"
               raise
           else:
               parentEntry = copy.deepcopy(FILE)
               parentEntry['LeaseKey']   = uuid.generate()
               parentEntry['LeaseState'] = SMB2_LEASE_NONE 
               self.GlobalFileTable[parentDir] = parentEntry 
               
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_CREATE
        packet['TreeID']  = treeId
        if self._Session['TreeConnectTable'][treeId]['IsDfsShare'] is True:
            packet['Flags'] = SMB2_FLAGS_DFS_OPERATIONS

        smb2Create = SMB2Create()
        smb2Create['SecurityFlags']        = 0
        smb2Create['RequestedOplockLevel'] = oplockLevel
        smb2Create['ImpersonationLevel']   = impersonationLevel
        smb2Create['DesiredAccess']        = desiredAccess
        smb2Create['FileAttributes']       = fileAttributes
        smb2Create['ShareAccess']          = shareMode
        smb2Create['CreateDisposition']    = creationDisposition
        smb2Create['CreateOptions']        = creationOptions
       
        smb2Create['NameLength']           = len(fileName)*2
        if fileName != '':
            smb2Create['Buffer']               = fileName.encode('utf-16le')
        else:
            smb2Create['Buffer']               = '\x00'

        if createContexts is not None:
            smb2Create['Buffer'] += createContexts
        else:
            smb2Create['CreateContextsOffset'] = 0
            smb2Create['CreateContextsLength'] = 0

        packet['Data'] = smb2Create

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            createResponse = SMB2Create_Response(ans['Data'])

            openFile = copy.deepcopy(OPEN)
            openFile['FileID']      = createResponse['FileID']
            openFile['TreeConnect'] = treeId
            openFile['Oplocklevel'] = oplockLevel
            openFile['Durable']     = False
            openFile['ResilientHandle']    = False
            openFile['LastDisconnectTime'] = 0
            openFile['FileName'] = pathName

            # ToDo: Complete the OperationBuckets
            if self._Connection['Dialect'] == SMB2_DIALECT_30:
                openFile['DesiredAccess']     = oplockLevel
                openFile['ShareMode']         = oplockLevel
                openFile['CreateOptions']     = oplockLevel
                openFile['FileAttributes']    = oplockLevel
                openFile['CreateDisposition'] = oplockLevel

            # ToDo: Process the contexts            
            self._Session['OpenTable'][str(createResponse['FileID'])] = openFile

            # The client MUST generate a handle for the Open, and it MUST 
            # return success and the generated handle to the calling application.
            # In our case, str(FileID)
            return str(createResponse['FileID'])

    def close(self, treeId, fileId):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_CLOSE
        packet['TreeID']  = treeId

        smbClose = SMB2Close()
        smbClose['Flags']  = 0
        smbClose['FileID'] = fileId
        
        packet['Data'] = smbClose

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            del(self.GlobalFileTable[self._Session['OpenTable'][fileId]['FileName']])
            del(self._Session['OpenTable'][fileId])
             
            # ToDo Remove stuff from GlobalFileTable
            return True

    def read(self, treeId, fileId, offset = 0, bytesToRead = 0, waitAnswer = True):
        # IMPORTANT NOTE: As you can see, this was coded as a recursive function
        # Hence, you can exhaust the memory pretty easy ( large bytesToRead )
        # This function should NOT be used for reading files directly, but another higher
        # level function should be used that will break the read into smaller pieces

        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_READ
        packet['TreeID']  = treeId

        if self._Connection['MaxReadSize'] < bytesToRead:
            maxBytesToRead = self._Connection['MaxReadSize']
        else: 
            maxBytesToRead = bytesToRead

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBytesToRead - 1) / 65536)
        else: 
            maxBytesToRead = min(65536,bytesToRead)

        smbRead = SMB2Read()
        smbRead['Padding']  = 0x50
        smbRead['FileID']   = fileId
        smbRead['Length']   = maxBytesToRead
        smbRead['Offset']   = offset
        packet['Data'] = smbRead

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            readResponse = SMB2Read_Response(ans['Data'])
            retData = readResponse['Buffer']
            if readResponse['DataRemaining'] > 0:
                retData += self.read(treeId, fileId, offset+len(retData), readResponse['DataRemaining'], waitAnswer)
            return retData
       
    def write(self, treeId, fileId, data, offset = 0, bytesToWrite = 0, waitAnswer = True):
        # IMPORTANT NOTE: As you can see, this was coded as a recursive function
        # Hence, you can exhaust the memory pretty easy ( large bytesToWrite )
        # This function should NOT be used for writing directly to files, but another higher
        # level function should be used that will break the writes into smaller pieces

        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_WRITE
        packet['TreeID']  = treeId

        if self._Connection['MaxWriteSize'] < bytesToWrite:
            maxBytesToWrite = self._Connection['MaxWriteSize']
        else: 
            maxBytesToWrite = bytesToWrite

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBytesToWrite - 1) / 65536)
        else: 
            maxBytesToWrite = min(65536,bytesToWrite)

        smbWrite = SMB2Write()
        smbWrite['FileID'] = fileId
        smbWrite['Length'] = maxBytesToWrite
        smbWrite['Offset'] = offset
        smbWrite['WriteChannelInfoOffset'] = 0
        smbWrite['Buffer'] = data[:maxBytesToWrite]
        packet['Data'] = smbWrite

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            writeResponse = SMB2Write_Response(ans['Data'])
            bytesWritten = writeResponse['Count']
            if bytesWritten < bytesToWrite:
                bytesWritten += self.write(treeId, fileId, data[bytesWritten:], offset+bytesWritten, bytesToWrite-bytesWritten, waitAnswer)
            return bytesWritten

    def queryDirectory(self, treeId, fileId, searchString = '*', resumeIndex = 0, informationClass = FILENAMES_INFORMATION, maxBufferSize = None, enumRestart = False, singleEntry = False):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_QUERY_DIRECTORY
        packet['TreeID']  = treeId

        queryDirectory = SMB2QueryDirectory()
        queryDirectory['FileInformationClass'] = informationClass
        if resumeIndex != 0 :
            queryDirectory['Flags'] = SMB2_INDEX_SPECIFIED
        queryDirectory['FileIndex'] = resumeIndex
        queryDirectory['FileID']    = fileId
        if maxBufferSize is None:
            maxBufferSize = self._Connection['MaxReadSize']
        queryDirectory['OutputBufferLength'] = maxBufferSize
        queryDirectory['FileNameLength']     = len(searchString)*2
        queryDirectory['Buffer']             = searchString.encode('utf-16le')

        packet['Data'] = queryDirectory

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBufferSize - 1) / 65536)

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            queryDirectoryResponse = SMB2QueryDirectory_Response(ans['Data'])
            return queryDirectoryResponse['Buffer']

    def echo(self):
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_ECHO
        smbEcho = SMB2Echo()
        packet['Data'] = smbEcho
        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            return True

    def cancel(self, packetID):
        packet = self.SMB_PACKET()
        packet['Command']   = SMB2_CANCEL
        packet['MessageID'] = packetID

        smbCancel = SMB2Cancel()

        packet['Data']      = smbCancel
        packetID = self.sendSMB(packet)

    def ioctl(self, treeId, fileId = None, ctlCode = -1, flags = 0, inputBlob = '',  maxInputResponse = None, maxOutputResponse = None, waitAnswer = 1):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if fileId is None:
            fileId = '\xff'*16
        else:
            if self._Session['OpenTable'].has_key(fileId) is False:
                raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command']            = SMB2_IOCTL
        packet['TreeID']             = treeId
       
        smbIoctl = SMB2Ioctl()
        smbIoctl['FileID']             = fileId
        smbIoctl['CtlCode']            = ctlCode
        smbIoctl['MaxInputResponse']   = maxInputResponse
        smbIoctl['MaxOutputResponse']  = maxOutputResponse
        smbIoctl['InputCount']         = len(inputBlob)
        if len(inputBlob) == 0:
            smbIoctl['InputOffset'] = 0
            smbIoctl['Buffer']      = '\x00'
        else:
            smbIoctl['Buffer']             = inputBlob
        smbIoctl['OutputOffset']       = 0
        smbIoctl['MaxOutputResponse']  = maxOutputResponse
        smbIoctl['Flags']              = flags

        packet['Data'] = smbIoctl
 
        packetID = self.sendSMB(packet)

        if waitAnswer == 0:
            return True

        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbIoctlResponse = SMB2Ioctl_Response(ans['Data'])
            return smbIoctlResponse['Buffer']

    def flush(self,treeId, fileId):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_FLUSH
        packet['TreeID']  = treeId

        smbFlush = SMB2Flush()
        smbFlush['FileID'] = fileId

        packet['Data'] = smbFlush

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbFlushResponse = SMB2Flush_Response(ans['Data'])
            return True

    def lock(self, treeId, fileId, locks, lockSequence = 0):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_LOCK
        packet['TreeID']  = treeId

        smbLock = SMB2Lock()
        smbLock['FileID']       = fileId
        smbLock['LockCount']    = len(locks)
        smbLock['LockSequence'] = lockSequence
        smbLock['Locks']        = ''.join(str(x) for x in locks)

        packet['Data'] = smbLock

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbFlushResponse = SMB2Lock_Response(ans['Data'])
            return True

        # ToDo:
        # If Open.ResilientHandle is TRUE or Connection.SupportsMultiChannel is TRUE, the client MUST
        # do the following:
        # The client MUST scan through Open.OperationBuckets and find an element with its Free field
        # set to TRUE. If no such element could be found, an implementation-specific error MUST be
        # returned to the application.
        # Let the zero-based array index of the element chosen above be referred to as BucketIndex, and
        # let BucketNumber = BucketIndex +1.
        # Set Open.OperationBuckets[BucketIndex].Free = FALSE
        # Let the SequenceNumber of the element chosen above be referred to as BucketSequence.
        # The LockSequence field of the SMB2 lock request MUST be set to (BucketNumber<< 4) +
        # BucketSequence.
        # Increment the SequenceNumber of the element chosen above using MOD 16 arithmetic.

    def logoff(self):
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_LOGOFF

        smbLogoff = SMB2Logoff()

        packet['Data'] = smbLogoff

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            return True

    def queryInfo(self, treeId, fileId, inputBlob = '', infoType = SMB2_0_INFO_FILE, fileInfoClass = SMB2_FILE_STANDARD_INFO, additionalInformation = 0, flags = 0 ):
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if self._Session['OpenTable'].has_key(fileId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_QUERY_INFO
        packet['TreeID']  = treeId

        queryInfo = SMB2QueryInfo()
        queryInfo['FileID']                = fileId
        queryInfo['InfoType']              = SMB2_0_INFO_FILE 
        queryInfo['FileInfoClass']         = fileInfoClass 
        queryInfo['OutputBufferLength']    = 65535
        queryInfo['AdditionalInformation'] = additionalInformation
        if len(inputBlob) == 0:
            queryInfo['InputBufferOffset'] = 0
            queryInfo['Buffer']            = '\x00'
        else:
            queryInfo['InputBufferLength'] = len(inputBlob)
            queryInfo['Buffer']            = inputBlob
        queryInfo['Flags']                 = flags

        packet['Data'] = queryInfo
        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            queryResponse = SMB2QueryInfo_Response(ans['Data'])
            return queryResponse['Buffer']

    ######################################################################
    # Higher level functions

    def list_path(self, shareName, path, password = None):
        # ToDo: Handle situations where share is password protected
        path = string.replace(path,'/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            # ToDo, we're assuming it's a directory, we should check what the file type is
            fileId = self.create(treeId, ntpath.dirname(path), FILE_READ_ATTRIBUTES | FILE_READ_DATA ,FILE_SHARE_READ | FILE_SHARE_WRITE |FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPEN, 0) 
            res = ''
            files = []
            import smb
            while True:
                try:
                    res = self.queryDirectory( treeId, fileId, ntpath.basename(path), maxBufferSize = 65535 )
                    nextOffset = 1
                    while nextOffset != 0:
                        fileInfo = smb.SMBFindFileNamesInfo(smb.SMB.FLAGS2_UNICODE)
                        fileInfo.fromString(res)
                        files.append(smb.SharedFile(0,0,0,0,0,0,fileInfo['FileName'].decode('utf-16le'), fileInfo['FileName'].decode('utf-16le')))
                        nextOffset = fileInfo['NextEntryOffset']
                        res = res[nextOffset:]
                except SessionError, e:
                    if (e.get_error_code()) != STATUS_NO_MORE_FILES:
                        raise
                    break 
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId) 

        return files

    def mkdir(self, shareName, pathName, password = None):
        # ToDo: Handle situations where share is password protected
        pathName = string.replace(pathName,'/', '\\')
        pathName = ntpath.normpath(pathName)
        if len(pathName) > 0 and pathName[0] == '\\':
            pathName = pathName[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            fileId = self.create(treeId, pathName,GENERIC_ALL ,FILE_SHARE_READ | FILE_SHARE_WRITE |FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATE, 0)          
        finally:
            if fileId is not None:
                self.close(treeId, fileId)            
            self.disconnectTree(treeId) 

        return True

    def rmdir(self, shareName, pathName, password = None):
        # ToDo: Handle situations where share is password protected
        pathName = string.replace(pathName,'/', '\\')
        pathName = ntpath.normpath(pathName)
        if len(pathName) > 0 and pathName[0] == '\\':
            pathName = pathName[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            fileId = self.create(treeId, pathName,GENERIC_ALL | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE |FILE_SHARE_DELETE, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_OPEN, 0)          
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId) 

        return True

    def retr_file(self, shareName, path, callback, mode = FILE_OPEN, offset = 0, password = None):
        # ToDo: Handle situations where share is password protected
        path = string.replace(path,'/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)
        fileId = None
        import smb
        try:
            fileId = self.create(treeId, path, FILE_READ_DATA, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE, mode, 0 )
            res = self.queryInfo(treeId, fileId)
            fileInfo = smb.SMBQueryFileStandardInfo(res)
            fileSize = fileInfo['EndOfFile']
            if (fileSize-offset) < self._Connection['MaxReadSize']:
                data = self.read(treeId, fileId, offset, fileSize-offset)
                callback(data)
            else:
                written = 0
                toBeRead = fileSize-offset
                while written < (toBeRead):
                    data = self.read(treeId, fileId, offset, self._Connection['MaxReadSize'])
                    written += len(data)
                    offset  += len(data)
                    callback(data)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId) 

    def stor_file(self, shareName, path, callback, mode = FILE_OVERWRITE_IF, offset = 0, password = None):
        # ToDo: Handle situations where share is password protected
        path = string.replace(path,'/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)
        fileId = None
        try:
            fileId = self.create(treeId, path, FILE_WRITE_DATA, FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE, mode, 0 )
            finished = False
            writeOffset = offset
            while not finished:
                data = callback(self._Connection['MaxWriteSize'])
                if len(data) == 0:
                    break
                written = self.write(treeId, fileId, data, writeOffset, len(data))
                writeOffset += written
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

    def waitNamedPipe(self, treeId, pipename, timeout = 5):
        pipename = ntpath.basename(pipename)
        if self._Session['TreeConnectTable'].has_key(treeId) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if len(pipename) > 0xffff:
            raise SessionError(STATUS_INVALID_PARAMETER)

        pipeWait = FSCTL_PIPE_WAIT_STRUCTURE()
        pipeWait['Timeout']          = timeout*100000
        pipeWait['NameLength']       = len(pipename)*2
        pipeWait['TimeoutSpecified'] = 1
        pipeWait['Name']             = pipename.encode('utf-16le')

        return self.ioctl(treeId, None, FSCTL_PIPE_WAIT,flags=SMB2_0_IOCTL_IS_FSCTL, inputBlob=pipeWait, maxInputResponse = 0, maxOutputResponse=0)
        

        

    ######################################################################
    # Backward compatibility functions for SMB1 and DCE Transports
    # NOTE: It is strongly recommended not to use these commands
    # when implementing new client calls.
    get_server_name   = getServerName
    get_server_domain = getServerDomain
    get_remote_name   = getServerName
    get_remote_host   = getServerIP

    def doesSupportNTLMv2(self):
        # Always true :P 
        return True
    
    def is_login_required(self):
        # Always true :P 
        return True

    tree_connect_andx = connectTree
    tree_connect      = connectTree
    connect_tree      = connectTree
    disconnect_tree   = disconnectTree 
    set_timeout       = setTimeout

    def nt_create_andx(self, treeId, fileName, smb_packet=None, cmd = None):
        if len(fileName) > 0 and fileName[0] == '\\':
            fileName = fileName[1:]
 
        if cmd is not None:
            import smb
            ntCreate = smb.SMBCommand(data = str(cmd))
            params = smb.SMBNtCreateAndX_Parameters(ntCreate['Parameters'])
            return self.create(treeId, fileName, params['AccessMask'], params['ShareAccess'],
                               params['CreateOptions'], params['Disposition'], params['FileAttributes'],
                               params['Impersonation'], params['SecurityFlags'])
                               
        else:
            return self.create(treeId, fileName, 
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |
                    FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, 0 )
                    
    def get_socket(self):
        return self._NetBIOSSession.get_socket()


    def write_andx(self,tid,fid,data, offset = 0, wait_answer=1, write_pipe_mode = False, smb_packet=None):
        # ToDo: Handle the custom smb_packet situation
        return self.write(tid, fid, data, offset, len(data))

    def TransactNamedPipe(self, tid, fid, data, noAnswer = 0, waitAnswer = 1, offset = 0):
        return self.ioctl(tid, fid, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL, data, maxOutputResponse = 65535, waitAnswer = noAnswer | waitAnswer)

    def TransactNamedPipeRecv(self):
        ans = self.recvSMB()

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbIoctlResponse = SMB2Ioctl_Response(ans['Data'])
            return smbIoctlResponse['Buffer']


    def read_andx(self, tid, fid, offset=0, max_size = None, wait_answer=1, smb_packet=None):
        # ToDo: Handle the custom smb_packet situation
        if max_size is None:
            max_size = self._Connection['MaxReadSize']
        return self.read(tid, fid, offset, max_size, wait_answer)

    def list_shared(self):
        # In the context of SMB2/3, forget about the old LANMAN, throw NOT IMPLEMENTED
        raise SessionError(STATUS_NOT_IMPLEMENTED)

    def open_andx(self, tid, fileName, open_mode, desired_access):
        # ToDo Return all the attributes of the file
        if len(fileName) > 0 and fileName[0] == '\\':
            fileName = fileName[1:]

        fileId = self.create(tid,fileName,desired_access, open_mode, FILE_NON_DIRECTORY_FILE, open_mode, 0)
        return fileId, 0, 0, 0, 0, 0, 0, 0, 0

