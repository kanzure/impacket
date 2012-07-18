#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Simple SMB Server, check smb.conf for details
#
# Author:
#  Alberto Solino <beto@coresecurity.com>
#

from impacket import smbserver

server = smbserver.SMBSERVER(('0.0.0.0',445))
server.processConfigFile('smb.conf')
# Uncomment this is you want the SMBServer to redirect all the \srvsvc pipe 
# calls to another DCERPC Server
# You might need to run srvsvcserver.py
# This is gonna be needed if you want Windows 7 users to connect to the server due 
# to a nasty bug in the Win7 when asking for shares (it will timeout for minutes before asking to 
# LANMAN)
#server.registerNamedPipe('srvsvc',('0.0.0.0',4344))
server.serve_forever()
