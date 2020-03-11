# samba-cohesity
Repo to share samba changes made by Cohesity. This repository contains changes
made by cohesity on top of samba version 4.5.16. The following files have been
modified to make the library adheree to the use case at Cohesity:

auth/ntlmssp/ntlmssp_client.c
docs-xml/smbdotconf/winbind/winbindscantrusteddomains.xml
lib/util/charset/iconv.c
lib/util/talloc_stack.c
lib/util/talloc_stack.h
source3/include/libsmbclient.h
source3/include/msdfs.h
source3/libads/sitename_cache.c
source3/libnet/libnet_join.c
source3/librpc/idl/libnet_join.idl
source3/libsmb/clidfs.c
source3/libsmb/clispnego.c
source3/libsmb/libsmb_wrappers.c
source3/libsmb/wscript
source3/param/loadparm.c
source3/utils/net_ads.c
source3/winbindd/winbindd.c
source4/torture/smb2/acls.c
source4/torture/smb2/compound.c
source4/torture/smb2/connect.c
source4/torture/smb2/create.c
source4/torture/smb2/delete-on-close.c
source4/torture/smb2/dir.c
source4/torture/smb2/dosmode.c
source4/torture/smb2/durable_v2_open.c
source4/torture/smb2/getinfo.c
source4/torture/smb2/ioctl.c
source4/torture/smb2/lock.c
source4/torture/smb2/notify.c
source4/torture/smb2/oplock.c
source4/torture/smb2/read.c
source4/torture/smb2/rename.c
source4/torture/smb2/session.c
source4/torture/smb2/setinfo.c
source4/torture/smb2/smb2.c
source4/torture/smb2/util.c
