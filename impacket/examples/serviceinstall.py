# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Service Install Helper library used by psexec and smbrelayx
# You provide an already established connection and an exefile
# (or class that mimics a file class) and this will install and
# execute the service, and then uninstall (install(), uninstall().
# It tries to take care as much as possible to leave everything clean.
#
# Author:
#  Alberto Solino (bethus@gmail.com)
#

import random
import string

from impacket.dcerpc import srvsvc, dcerpc, svcctl, transport
from impacket import smb,smb3
from impacket.smbconnection import *

class ServiceInstall():
    def __init__(self, SMBObject, exeFile, service_name=None, filename=None):
        """
        @param service_name: the name that the service will use when running on
        Windows.
        @param filename: save the upload exe with this filename on the remote
        machine.
        """

        if not service_name:
            service_name = ''.join([random.choice(string.letters) for i in range(4)])

        if not filename:
            filename = ''.join([random.choice(string.letters) for i in range(8)]) + '.exe'

        self._rpctransport = 0
        self.__service_name = service_name
        self.__binary_service_name = filename
        self.__exeFile = exeFile

        # We might receive two different types of objects, always end up
        # with a SMBConnection one
        if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3):
            self.connection = SMBConnection(existingConnection = SMBObject)
        else:
            self.connection = SMBObject

        self.share = ''

    def getShare(self):
        return self.share

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        print "[*] Requesting shares on %s....." % (self.connection.getRemoteHost())
        try:
            self._rpctransport = transport.SMBTransport('','',filename = r'\srvsvc', smb_connection = self.connection)
            self._dce = dcerpc.DCERPC_v5(self._rpctransport)
            self._dce.connect()

            self._dce.bind(srvsvc.MSRPC_UUID_SRVSVC)
            srv_svc = srvsvc.DCERPCSrvSvc(self._dce)
            resp = srv_svc.get_share_enum_1(self._rpctransport.get_dip())
            return resp
        except:
            print "[!] Error requesting shares on %s, aborting....." % (self.connection.getRemoteHost())
            raise

    def createService(self, handle, share, path):
        print "[*] Creating service %s on %s....." % (self.__service_name, self.connection.getRemoteHost())


        # First we try to open the service in case it exists. If it does, we remove it.
        try:
            resp = self.rpcsvc.OpenServiceW(handle, self.__service_name.encode('utf-16le'))
        except Exception, e:
            if e.get_error_code() == svcctl.ERROR_SERVICE_DOES_NOT_EXISTS:
                # We're good, pass the exception
                pass
            else:
                raise
        else:
            # It exists, remove it
            self.rpcsvc.DeleteService(resp['ContextHandle'])
            self.rpcsvc.CloseServiceHandle(resp['ContextHandle'])

        # Create the service
        command = '%s\\%s' % (path, self.__binary_service_name)
        try:
            resp = self.rpcsvc.CreateServiceW(handle, self.__service_name.encode('utf-16le'), self.__service_name.encode('utf-16le'), command.encode('utf-16le'))
        except:
            print "[!] Error creating service %s on %s" % (self.__service_name, self.connection.getRemoteHost())
            raise
        else:
            return resp['ContextHandle']

    def openSvcManager(self):
        print "[*] Opening SVCManager on %s....." % self.connection.getRemoteHost()
        # Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport('','',filename = r'\svcctl', smb_connection = self.connection)
        self._dce = dcerpc.DCERPC_v5(self._rpctransport)
        self._dce.connect()
        self._dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.rpcsvc = svcctl.DCERPCSvcCtl(self._dce)
        try:
            resp = self.rpcsvc.OpenSCManagerW()
        except:
            print "[!] Error opening SVCManager on %s....." % self.connection.getRemoteHost()
            return 0
        else:
            return resp['ContextHandle']

    def copy_file(self, src, tree, dst):
        print "[*] Uploading file %s" % dst
        if isinstance(src, str):
            # We have a filename
            fh = open(src, 'rb')
        else:
            # We have a class instance, it must have a read method
            fh = src
        f = dst
        pathname = string.replace(f,'/','\\')
        try:
            self.connection.putFile(tree, pathname, fh.read)
        except:
            print "[!] Error uploading file %s, aborting....." % dst
            raise
        fh.close()

    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        for i in shares:
            if i['Type'] == smb.SHARED_DISK or i['Type'] == smb.SHARED_DISK_HIDDEN:
               share = i['NetName'].decode('utf-16le')[:-1]
               try:
                   self.connection.createDirectory(share,'BETO')
               except:
                   # Can't create, pass
                   print '[!] No written share found, aborting...'
                   raise
               else:
                   print '[*] Found writable share %s' % share
                   self.connection.deleteDirectory(share,'BETO')
                   return str(share)
        return None

    def install(self):
        if self.connection.isGuestSession():
            print "[!] Authenticated as Guest. Aborting"
            self.connection.logoff()
            del(self.connection)
        else:
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                res = self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = True
                svcManager = self.openSvcManager()
                if svcManager != 0:
                    serverName = self.connection.getServerName()
                    if serverName != '':
                       path = '\\\\%s\\%s' % (serverName, self.share)
                    else:
                       path = '\\\\127.0.0.1\\' + self.share
                    service = self.createService(svcManager, self.share, path)
                    serviceCreated = True
                    if service != 0:
                        parameters = [ '%s\\%s' % (path,self.__binary_service_name), '%s\\%s' % (path, '') ]
                        # Start service
                        print '[*] Starting service %s.....' % self.__service_name
                        try:
                            self.rpcsvc.StartServiceW(service)
                        except:
                            pass
                        self.rpcsvc.CloseServiceHandle(service)
                    self.rpcsvc.CloseServiceHandle(svcManager)
            except Exception, e:
                print "[!] Error performing the installation, cleaning up: %s" %e
                try:
                    self.rpcsvc.StopService(service)
                except:
                    pass
                if fileCopied is True:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated is True:
                    try:
                        self.rpcsvc.DeleteService(service)
                    except:
                        pass

    def uninstall(self):
        fileCopied = True
        serviceCreated = True
        # Do the stuff here
        try:
            # Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0:
                resp = self.rpcsvc.OpenServiceA(svcManager, self.__service_name)
                service = resp['ContextHandle']
                print '[*] Stoping service %s.....' % self.__service_name
                try:
                    self.rpcsvc.StopService(service)
                except:
                    pass
                print '[*] Removing service %s.....' % self.__service_name
                self.rpcsvc.DeleteService(service)
                self.rpcsvc.CloseServiceHandle(service)
                self.rpcsvc.CloseServiceHandle(svcManager)
            print '[*] Removing file %s.....' % self.__binary_service_name
            self.connection.deleteFile(self.share, self.__binary_service_name)
        except Exception, e:
            print "[!] Error performing the uninstallation, cleaning up"
            try:
                self.rpcsvc.StopService(service)
            except:
                pass
            if fileCopied is True:
                try:
                    self.connection.deleteFile(self.share, self.__binary_service_name)
                except:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                    pass
            if serviceCreated is True:
                try:
                    self.rpcsvc.DeleteService(service)
                except:
                    pass

