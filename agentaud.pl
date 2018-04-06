#!/usr/local/bin/perl -w
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------

#  perl agentaud.pl diagnostic_log
#
#  Create a report on agent row results from
#  kpxrpcrq tracing
#
#  john alvord, IBM Corporation, 22 December 2014
#  jalvord@us.ibm.com
#
# tested on Windows Activestate 5.20.1
#
# $DB::single=2;   # remember debug breakpoint

$gVersion = 0.87000;
$gWin = (-e "C:/") ? 1 : 0;       # determine Windows versus Linux/Unix for detail settings

## Todos

## Todos
#  Handle Agent side historical traces - needs definition and work.

#          Data row is filtered
# (54931626.0DA9-11:kdsflt1.c,1427,"FLT1_FilterRecord") Entry
# (54931626.0DAC-11:kdsflt1.c,1464,"FLT1_FilterRecord") Exit: 0x1      <=== row fails filter
# (54931625.023C-3:kdsflt1.c,1464,"FLT1_FilterRecord") Exit: 0x0       <=== row passes filter

#         Potential row data is produced - including sitname
# (54931626.0DAE-11:kraaevxp.cpp,501,"CreateSituationEvent") *EV-INFO: Input event: obj=0x1111FA530, type=5, excep=0, numbRow=1, rowData=0x110ADF640, status=0, sitname="UNIX_LAA_Bad_su_to_root_Warning"
# (54931626.0DB2-11:kraaevxp.cpp,562,"CreateSituationEvent") *EV-INFO: Use request <1111FA530> handle <294650831> element <111167790>
# (54931626.0DB4-11:kraaevxp.cpp,414,"EnqueueEventWork") *EV-INFO: Enqueue event work element 111167790 to Dispatcher
# (54931626.0DB5-11:kraaprdf.cpp,228,"CheckForException") Exit: 0x0
# (54931626.0DB7-11:kraulleb.cpp,194,"AddData") Exit: 0x0
# (unit:kraaevxp,Entry="CreateSituationEvent" detail er)
#
#         No data is sent
# (54931626.0DBB-11:kraadspt.cpp,868,"sendDataToProxy") Entry
# (54931626.0DBD-11:kraadspt.cpp,955,"sendDataToProxy") Exit

#         Some data is sent
# (54931626.0DBB-11:kraadspt.cpp,868,"sendDataToProxy") Entry
# (54931625.04D0-3:kraadspt.cpp,889,"sendDataToProxy") Sending 14 rows for UNIX_LAA_Log_Size_Warning KUL.ULMONLOG, <722472833,294650830>.
# (54931626.0DBD-11:kraadspt.cpp,955,"sendDataToProxy") Exit

## !5A9E41FB.0000!========================>  IBM Tivoli RAS1 Service Log  <========================
## +5A9E41FB.0000      System Name: USRD12ZDU2005               Process ID: 1684
## +5A9E41FB.0000     Program Name: k5pagent                     User Name: SYSTEM
## +5A9E41FB.0000        Task Name: k5pagent                   System Type: Windows;6.2
## +5A9E41FB.0000   MAC1_ENV Macro: 0xC112                      Start Date: 2018/03/06
## +5A9E41FB.0000       Start Time: 07:23:39                     CPU Count: 2
## +5A9E41FB.0000        Page Size: 4K                         Phys Memory: 4096M
## +5A9E41FB.0000      Virt Memory: 134217728M                  Page Space: 4800M
## +5A9E41FB.0000   UTC Start Time: 5a9e41fb                      ITM Home: C:\IBM\ITM
## +5A9E41FB.0000      ITM Process: usrd12zdu2005_5p
## +5A9E41FB.0000    Service Point: system.usrd12zdu2005_5p

## (5A9E41FD.0055-698:kraarreg.cpp,3932,"IRA_SetConnectCMSLIST") *INFO: 01 IP.SPIPE:146.89.140.75
## (5A9E41FD.0056-698:kraarreg.cpp,3932,"IRA_SetConnectCMSLIST") *INFO: 02 IP.PIPE:146.89.140.75
## (5A9E41FD.0057-698:kraarreg.cpp,3946,"IRA_SetConnectCMSLIST") *INFO: Primary TEMS set to <IP.SPIPE:146.89.140.75> host <146.89.140.75>
## (5A9E41FE.0081-7BC:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.75: D2900386, KDEP_pcb_t @ 3760F20 created

## (5AA2E3F5.0004-13E0:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.76: D2F00373, KDEP_pcb_t @ 37618E0 created
## (5AAB62B3.0004-1BA0:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.76: D310034F, KDEP_pcb_t @ 3760D80 created

## (5AA6520D.0000-7DC:kdepdpc.c,62,"KDEP_DeletePCB") D2F00373: KDEP_pcb_t deleted



## (5AA2E3F4.0002-13E0:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.75: D2D0037C, KDEP_pcb_t @ 3761330 created
## (5AA2E3F5.0000-13E0:kdepdpc.c,62,"KDEP_DeletePCB") D2D0037C: KDEP_pcb_t deleted
## (5AA2E3F5.0004-13E0:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.76: D2F00373, KDEP_pcb_t @ 37618E0 created
## (5AA2E3F5.0005-1A34:kdebpli.c,211,"KDEBP_Listen") pipe 2 assigned: PLE=1F4F9F0, count=1, hMon=D2B00381

## (5AA31B32.0001-9F0:kdepnpc.c,138,"KDEP_NewPCB") 146.89.140.75: D470034C, KDEP_pcb_t @ 375FBA0 created
## (5AA31B33.0000-9F0:kdepdpc.c,62,"KDEP_DeletePCB") D470034C: KDEP_pcb_t deleted


## (5AA1C09A.0001-11F0:khdxbase.cpp,339,"setError")
## +5AA1C09A.0001  ERROR MESSAGE: "Unable to open Metafile "C:\IBM\ITM\TMAITM~1\logs\History\K5P\K5PMANAGED.hdr" "
## (5AA1C09A.0002-11F0:khdxbase.cpp,336,"setError")
## +5AA1C09A.0002  Error Type= CTX_MetafileNotfound


# CPAN packages used
use Data::Dumper;               # debug
#use warnings::unused; # debug used to check for unused variables
use Time::Local;
use POSIX qw{strftime};


my $start_date = "";
my $start_time = "";
my $local_diff = -1;

# This is a typical log scraping program. The log data looks like this
#
# Distributed with a situation:
# (4D81D817.0000-A17:kpxrpcrq.cpp,749,"IRA_NCS_Sample") Rcvd 1 rows sz 220 tbl *.RNODESTS req HEARTBEAT <219213376,1892681576> node <Primary:INMUM01B2JTP01:NT>
#   Interesting failure cases
# (4FF79663.0003-4:kpxrpcrq.cpp,826,"IRA_NCS_Sample") Sample <665885373,2278557540> arrived with no matching request.
# (4FF794A9.0001-28:kpxrpcrq.cpp,802,"IRA_NCS_Sample") RPC socket change detected, initiate reconnect, node thp-gl-04:KUX!
#
# Distributed without situation
# (4D81D81A.0000-A1A:kpxrpcrq.cpp,749,"IRA_NCS_Sample") Rcvd 1 rows sz 816 tbl *.UNIXOS req  <418500981,1490027440> node <evoapcprd:KUX>
#
# z/OS RKLVLOG lines contain the same information but often split into two lines
# and the timestamp is in a different form.
#  2011.080 14:53:59.78 (005E-D61DDF8B:kpxrpcrq.cpp,749,"IRA_NCS_Sample") Rcvd 1 rows sz 220 tbl *.RNODESTS req HEARTBEAT <565183706,5
#  2011.080 14:53:59.79 65183700> node <IRAM:S8CMS1:SYS:STORAGE         >
#
# the data is identical otherwise
#
#  Too Big message
#   (4D75475E.0001-B00:kpxreqds.cpp,1695,"buildThresholdsFilterObject") Filter object too big (39776 + 22968),Table FILEINFO Situation SARM_UX_FileMonitoring2_Warn.
#
#  SOAP IP address
#  (4D9633C2.0010-11:kshdhtp.cpp,363,"getHeaderValue") Header is <ip.ssl:#10.41.100.21:38317>
#
#  SOAP SQL
#  (4D9633C2.0020-11:kshreq.cpp,881,"buildSQL") Using pre-built SQL: SELECT NODE, AFFINITIES, PRODUCT, VERSION, RESERVED, O4ONLINE FROM O4SRV.INODESTS
#  (4D9633C3.0021-11:kshreq.cpp,1307,"buildSQL") Using SQL: SELECT CLCMD,CLCMD2,CREDENTIAL,CWD,KEY,MESSAGE,ACTSECURE,OPTIONS,RESPFILE,RUNASUSER,RUNASPWD,REQSTATUS,ACTPRTY,RESULT,ORIGINNODE FROM O4SRV.CLACTRMT WHERE  SYSTEM.PARMA("NODELIST", "swdc-risk1csc0:KUX", 18) AND  CLCMD =  N"/opt/IBM/custom/ChangeTEMS_1.00.sh PleaseReturnZero"
#
# To manage the differences, a state engine is used.
#  When set to 0 based on absence of -z option, the lines are processed directly
#
#  For RKLVLOG case the state is set to 1 at outset.
#  When 1, the first line is examined. RKLVLOGs can be in two forms. When
#  collected as a SYSOUT file, there is an initial printer control character
#  of "1" or " ", a printer control character. In that case all the lines have
#  a printer control character of blank. If recogonized a variable $offset
#  is set to value o1.
#
#  The second form is when the RKLVLOG is written directly to a disk file.
#  In this case the printer control characters are absent. For that case the
#  variable $offset is set to 0. When getting the data, $offset is used
#  calculations.
#
#  After state 1, state 2 is entered.
#
# When state=2, the input record is checked for the expected form of trace.
# If not, the next record is processed. If found, the partial line
# is captured and the state is set to 3. The timestamp is also captured.
# then the next record is processed.
#
# When state=3, the second part of the data is captured. The data is assembled
# as if it was a distributed record. The timestamp is converted to the
# distributed timestamp. The state is set to 2 and then the record is processed.
# Sometimes we don't know if there is a continuation or not. Thus we usually
# keep the prior record and add to it if the next one is not in correct form.
#
# Processing is typical log scraping. The target is identified, an associative
# array is used to look up prior cases, and the data is recorded. At the end
# the accumulated data is printed to standard output.

# pick up parameters and process

my $opt_z;
my $opt_zop;
my $opt_logpat;
my $opt_logpath;
my $full_logfn;
my $opt_v;
my $opt_vv;
my $workdel = "";
my $opt_cmdall;                                  # show all commands

sub gettime;                             # get time
sub getstamp;                            # convert epoch into slot stamp
sub sec2ltime;
sub do_rpt;


# following hashtable is a backup for calculating table lengths.
# Windows, Linux, Unix tables only at the moment

my %htabsize = (
   'KPX.RNODESTS'      => '220',
   'OMUNX.UNIXAMS'     => '212',
   'OMUNX.UNIXDUSERS'  => '1668',
   'OMUNX.UNIXDEVIC'   => '560',
   'OMUNX.UNIXLVOLUM'  => '1240',
   'OMUNX.UNIXLPAR'    => '1556',
   'OMUNX.FILEINFO'    => '4184',                     # missing from load projections
   'OMUNX.AIXPAGMEM'   => '208',
   'OMUNX.AIXMPIOATR'  => '560',
   'OMUNX.AIXMPIOSTS'  => '560',
   'OMUNX.AIXNETADPT'  => '1592',
   'OMUNX.UNIXPVOLUM'  => '552',
   'OMUNX.AIXSYSIO'    => '144',
   'OMUNX.UNIXVOLGRP'  => '336',
   'OMUNX.UNIXWPARCP'  => '432',
   'OMUNX.UNIXWPARFS'  => '1616',
   'OMUNX.UNIXWPARIN'  => '5504',
   'OMUNX.UNIXWPARNE'  => '1360',
   'OMUNX.UNIXWPARPM'  => '400',
   'OMUNX.UNIXDCSTAT'  => '184',
   'OMUNX.UNIXDISK'    => '1364',
   'OMUNX.UNIXDPERF'   => '832',
   'OMUNX.KUXPASSTAT'  => '1382',
   'OMUNX.KUXPASMGMT'  => '510',
   'OMUNX.KUXPASALRT'  => '484',
   'OMUNX.KUXPASCAP'   => '3062',
   'OMUNX.UNIXMACHIN'  => '508',
   'OMUNX.UNIXNFS'     => '492',
   'OMUNX.UNIXNET'     => '1600',
   'OMUNX.UNIXPS'      => '2784',
   'OMUNX.UNIXCPU'     => '360',
   'OMUNX.UNIXSOLZON'  => '598',
   'OMUNX.UNIXOS'      => '1084',
   'OMUNX.UNIXTOPCPU'  => '1844',
   'OMUNX.UNIXTOPMEM'  => '1864',
   'OMUNX.UNIXALLUSR'  => '160',
   'OMUNX.KUXDEVIC'    => '660',
   'OMUNX.UNIXGROUP'   => '136',
   'OMUNX.UNIXIPADDR'  => '546',
   'OMUNX.UNIXMEM'     => '560',
   'OMUNX.UNIXPING'    => '868',
   'OMUNX.UNXPRINTQ'   => '288',
   'OMUNX.UNIXTCP'     => '104',
   'OMUNX.UNIXUSER'    => '540',
   'KNT.ACTSRVPG'    => '376',
   'KNT.DHCPSRV'     => '272',
   'KNT.DNSDYNUPD'   => '264',
   'KNT.DNSMEMORY'   => '240',
   'KNT.DNSQUERY'    => '288',
   'KNT.DNSWINS'     => '248',
   'KNT.DNSZONET'    => '288',
   'KNT.FTPSTATS'    => '280',
   'KNT.FTPSVC'      => '216',
   'KNT.GOPHRSVC'    => '292',
   'KNT.HTTPCNDX'    => '248',
   'KNT.HTTPSRVC'    => '328',
   'KNT.ICMPSTAT'    => '324',
   'KNT.IISSTATS'    => '272',
   'KNT.INDEXSVC'    => '588',
   'KNT.INDEXSVCF'   => '556',
   'KNT.IPSTATS'     => '288',
   'KNT.JOBOBJ'      => '644',
   'KNT.JOBOBJD'     => '672',
   'KNT.KNTPASSTAT'  => '1390',
   'KNT.KNTPASMGMT'  => '526',
   'KNT.KNTPASALRT'  => '484',
   'KNT.KNTPASCAP'   => '2998',
   'KNT.NTMNTPT'     => '624',
   'KNT.MSMQIS'      => '244',
   'KNT.MSMQQUE'     => '424',
   'KNT.MSMQSVC'     => '252',
   'KNT.MSMQSESS'    => '312',
   'KNT.NETWRKIN'    => '476',
   'KNT.NETSEGMT'    => '180',
   'KNT.NNTPCMD'     => '328',
   'KNT.NNTPSRV'     => '312',
   'KNT.NTBIOSINFO'  => '656',
   'KNT.NTCACHE'     => '340',
   'KNT.NTCOMPINFO'  => '1232',
   'KNT.NTDEVDEP'    => '668',
   'KNT.NTDEVICE'    => '1148',
   'KNT.NTEVTLOG'    => '3132',
   'KNT.NTIPADDR'    => '614',
   'KNT.NTJOBOBJD'   => '692',
   'KNT.WTLOGCLDSK'  => '684',
   'KNT.WTMEMORY'    => '388',
   'KNT.NTMEMORY'    => '348',
   'KNT.NTLOGINFO'   => '1256',
   'KNT.NTNETWRKIN'  => '992',
   'KNT.NTNETWPORT'  => '772',
   'KNT.WTOBJECTS'   => '240',
   'KNT.NTPAGEFILE'  => '552',
   'KNT.WTPHYSDSK'   => '320',
   'KNT.NTPRTJOB'    => '1436',
   'KNT.NTPRINTER'   => '2424',
   'KNT.WTPROCESS'   => '1028',
   'KNT.NTPROCESS'   => '960',
   'KNT.NTPROCSSR'   => '192',
   'KNT.NTPROCINFO'  => '452',
   'KNT.NTPROCRSUM'  => '340',
   'KNT.NTREDIRECT'  => '476',
   'KNT.WTSERVER'    => '364',
   'KNT.WTSERVERQ'   => '220',
   'KNT.NTSERVERQ'   => '248',
   'KNT.NTSVCDEP'    => '680',
   'KNT.NTSERVICE'   => '1468',
   'KNT.WTSYSTEM'    => '900',
   'KNT.WTTHREAD'    => '328',
   'KNT.PRINTQ'      => '576',
   'KNT.PROCESSIO'   => '704',
   'KNT.KNTRASPT'    => '220',
   'KNT.KNTRASTOT'   => '288',
   'KNT.SMTPSRV'     => '368',
   'KNT.TCPSTATS'    => '252',
   'KNT.UDPSTATS'    => '236',
   'KNT.VMMEMORY'    => '128',
   'KNT.VMPROCSSR'   => '196',
   'KNT.WEBSVC'      => '392',
   'KLZ.KLZPASSTAT'  => '1382',
   'KLZ.KLZPASMGMT'  => '526',
   'KLZ.KLZPASALRT'  => '484',
   'KLZ.KLZPASCAP'   => '3062',
   'KLZ.KLZCPU'      => '232',
   'KLZ.KLZCPUAVG'   => '276',
   'KLZ.KLZDISK'     => '692',
   'KLZ.KLZDSKIO'    => '216',
   'KLZ.KLZDU'       => '408',
   'KLZ.KLZIOEXT'    => '412',
   'KLZ.KLZLPAR'     => '344',
   'KLZ.KLZNET'      => '365',
   'KLZ.KLZNFS'      => '384',
   'KLZ.KLZPROC'     => '1720',
   'KLZ.KLZPUSR'     => '1580',
   'KLZ.KLZRPC'      => '144',
   'KLZ.KLZSOCKD'    => '296',
   'KLZ.KLZSOCKS'    => '100',
   'KLZ.KLZSWPRT'    => '128',
   'KLZ.KLZSYS'      => '316',
   'KLZ.KLZTCP'      => '88',
   'KLZ.KLZLOGIN'    => '488',
   'KLZ.KLZVM'       => '380',
   'KLZ.LNXALLUSR'   => '152',
   'KLZ.LNXCPU'      => '252',
   'KLZ.LNXCPUAVG'   => '348',
   'KLZ.LNXCPUCON'   => '312',
   'KLZ.LNXDISK'     => '488',
   'KLZ.LNXDSKIO'    => '248',
   'KLZ.LNXDU'       => '204',
   'KLZ.LNXGROUP'    => '144',
   'KLZ.LNXPING'     => '228',
   'KLZ.LNXIOEXT'    => '440',
   'KLZ.LNXIPADDR'   => '546',
   'KLZ.LNXMACHIN'   => '828',
   'KLZ.LNXNET'      => '317',
   'KLZ.LNXNFS'      => '324',
   'KLZ.LNXOSCON'    => '440',
   'KLZ.LNXPROC'     => '1324',
   'KLZ.LNXPUSR'     => '1416',
   'KLZ.LNXRPC'      => '152',
   'KLZ.LNXSOCKD'    => '312',
   'KLZ.LNXSOCKS'    => '132',
   'KLZ.LNXSWPRT'    => '148',
   'KLZ.LNXSYS'      => '312',
   'KLZ.LNXLOGIN'    => '524',
   'KLZ.LNXVM'       => '336',
   'KUL.ULLOGENT'    => '2864',
   'KUL.ULMONLOG'    => '1988',
   'KPX.KPX48WPNET'  => '1328',
   'KPX.KPX50WPINF'  => '5448',
);


my %kdemsgx = (
   '00000000' => ["","KDE1_STC_OK"],
   '1DE00000' => ["","KDE1_STC_CANTBIND"],
   '1DE00001' => ["","KDE1_STC_NOMEMORY"],
   '1DE00002' => ["","KDE1_STC_TOOMANY"],
   '1DE00003' => ["","KDE1_STC_BADRAWNAME"],
   '1DE00004' => ["","KDE1_STC_BUFTOOLARGE"],
   '1DE00005' => ["","KDE1_STC_BUFTOOSMALL"],
   '1DE00006' => ["","KDE1_STC_ENDPOINTUNAVAILABLE"],
   '1DE00007' => ["","KDE1_STC_NAMEUNAVAILABLE"],
   '1DE00008' => ["","KDE1_STC_NAMENOTFOUND"],
   '1DE00009' => ["","KDE1_STC_CANTGETLOCALNAME"],
   '1DE0000A' => ["","KDE1_STC_SOCKETOPTIONERROR"],
   '1DE0000B' => ["","KDE1_STC_DISCONNECTED"],
   '1DE0000C' => ["","KDE1_STC_INVALIDNAMEFORMAT"],
   '1DE0000D' => ["","KDE1_STC_IOERROR"],
   '1DE0000E' => ["","KDE1_STC_NOTLISTENING"],
   '1DE0000F' => ["","KDE1_STC_NOTREADY"],
   '1DE00010' => ["","KDE1_STC_INVALIDFAMILY"],
   '1DE00011' => ["","KDE1_STC_INTERNALERROR"],
   '1DE00012' => ["","KDE1_STC_NOTEQUAL"],
   '1DE00013' => ["","KDE1_STC_INVALIDLENGTH"],
   '1DE00014' => ["","KDE1_STC_FUNCTIONUNAVAILABLE"],
   '1DE00015' => ["","KDE1_STC_ARGUMENTINCONSISTENCY"],
   '1DE00016' => ["","KDE1_STC_PROTOCOLERROR"],
   '1DE00017' => ["","KDE1_STC_MISSINGINFORMATION"],
   '1DE00018' => ["","KDE1_STC_DUPLICATEINFORMATION"],
   '1DE00019' => ["","KDE1_STC_ARGUMENTRANGE"],
   '1DE0001A' => ["","KDE1_STC_THREADSREQUIRED"],
   '1DE0001B' => ["syntax error",                                                              "KDE1_STC_SYNTAXERROR"],
   '1DE0001C' => ["KDE1_tvt_t deref member inconsistency",                                     "KDE1_STC_DEREFVALUEINCONSISTENT"],
   '1DE0001D' => ["protocol-name/protseq inconsistent",                                        "KDE1_STC_PROTSEQINCONSISTENT"],
   '1DE0001E' => ["cant create sna conversation",                                              "KDE1_STC_CANTCREATECONVERSATION"],
   '1DE0001F' => ["cant set sna synclevel",                                                    "KDE1_STC_CANTSETSYNCLEVEL"],
   '1DE00020' => ["cant set sna partner lu name",                                              "KDE1_STC_CANTSETPARTNERLUNAME"],
   '1DE00021' => ["cant set sna mode name",                                                    "KDE1_STC_CANTSETMODENAME"],
   '1DE00022' => ["cant set sna tpname",                                                       "KDE1_STC_CANTSETTPNAME"],
   '1DE00023' => ["cant allocate sna conversation",                                            "KDE1_STC_CANTALLOCATECONVERSATION"],
   '1DE00024' => ["cant create sna local lu",                                                  "KDE1_STC_CANTCREATELOCALLU"],
   '1DE00025' => ["cant define sna local tp",                                                  "KDE1_STC_CANTDEFINELOCALTP"],
   '1DE00026' => ["protocol method limit exceeded",                                            "KDE1_STC_TOOMANYMETHODS"],
   '1DE00027' => ["interface specification is invalid",                                        "KDE1_STC_PROTSEQINTERFACEINVALID"],
   '1DE00028' => ["method specification is invalid",                                           "KDE1_STC_PROTSEQMETHODINVALID"],
   '1DE00029' => ["protocol specification is invalid",                                         "KDE1_STC_PROTSEQPROTOCOLINVALID"],
   '1DE0002A' => ["family specification is invalid",                                           "KDE1_STC_PROTSEQFAMILYINVALID"],
   '1DE0002B' => ["side information profile name too long",                                    "KDE1_STC_SIPNAMETOOLONG"],
   '1DE0002C' => ["no server bindings available",                                              "KDE1_STC_SERVERNOTBOUND"],
   '1DE0002D' => ["buffer is reserved",                                                        "KDE1_STC_RESERVEDBUFFER"],
   '1DE0002E' => ["server is not listening",                                                   "KDE1_STC_SERVERNOTLISTENING"],
   '1DE0002F' => ["buffer is not valid",                                                       "KDE1_STC_INVALIDBUFFER"],
   '1DE00030' => ["the requested endpoint is in use",                                          "KDE1_STC_ENDPOINTINUSE"],
   '1DE00031' => ["all endpoints in the pool are in use",                                      "KDE1_STC_ENDPOINTPOOLEXHAUSTED"],
   '1DE00032' => ["invalid circuit handle",                                                    "KDE1_STC_BADCIRCUITHANDLE"],
   '1DE00033' => ["circuit handle is not currently in use",                                    "KDE1_STC_HANDLENOTINUSE"],
   '1DE00034' => ["operation was cancelled",                                                   "KDE1_STC_OPERATIONCANCELLED"],
   '1DE00035' => ["SNA Network ID doesn't match system definition",                            "KDE1_STC_NETIDMISMATCH"],
   '1DE00036' => ["Function must be performed prior to bind of setup data",                    "KDE1_STC_SETUPALREADYBOUND"],
   '1DE00037' => ["No transport providers are registered",                                     "KDE1_STC_NOTRANSPORTSREGISTERED"],
   '1DE00038' => ["Configuration handle invalid",                                              "KDE1_STC_BADCONFIGHANDLE"],
   '1DE00039' => ["unable to query local node information",                                    "KDE1_STC_CANTQUERYLOCALNODE"],
   '1DE0003A' => ["vector count out of range",                                                 "KDE1_STC_VECTORCOUNTINVALID"],
   '1DE0003B' => ["duplicate vector code encountered",                                         "KDE1_STC_DUPLICATEVECTOR"],
   '1DE0003C' => ["a required XID buffer was not received successfully",                       "KDE1_STC_RECEIVEXIDFAILURE"],
   '1DE0003D' => ["invalid XID buffer format",                                                 "KDE1_STC_INVALIDXIDBUFFER"],
   '1DE0003E' => ["unable to create pipe infrastructure",                                      "KDE1_STC_PIPECREATIONFAILED"],
   '1DE0003F' => ["target endpoint is not bound","KDE1_STC_ENDPOINTNOTBOUND"],
   '1DE00040' => ["target endpoint queueing limit reached","KDE1_STC_RECEIVELIMITEXCEEDED"],
   '1DE00041' => ["configuration keyword not found","KDE1_STC_KEYWORDNOTFOUND"],
   '1DE00042' => ["endpoint value not supported","KDE1_STC_INVALIDENDPOINT"],
   '1DE00043' => ["KDE_TRANSPORT error caused some values of this keyword to be ignored","KDE1_STC_KEYWORDVALUEIGNORED"],
   '1DE00044' => ["streaming packet synchronization lost","KDE1_STC_PACKETSYNCLOST"],
   '1DE00045' => ["connection procedure failed","KDE1_STC_CONNECTIONFAILURE"],
   '1DE00046' => ["unable to create any more interfaces","KDE1_STC_INTERFACELIMITREACHED"],
   '1DE00047' => ["transport provider is unavailable for use","KDE1_STC_TRANSPORTDISABLED"],
   '1DE00048' => ["transport provider failed to register any interfaces","KDE1_STC_NOINTERFACESREGISTERED"],
   '1DE00049' => ["transport provider registered too many interfaces","KDE1_STC_INTERFACELIMITEXCEEDED"],
   '1DE0004A' => ["unable to negotiate a secure connection using SSL","KDE1_STC_SSLFAILURE"],
   '1DE0004B' => ["unable to contact ephemeral endpoint","KDE1_STC_EPHEMERALENDPOINT"],
   '1DE0004C' => ["unable to perform request without a transport correlator","KDE1_STC_NEEDTRANSPORTCORRELATOR"],
   '1DE0004D' => ["transport correlator invalid","KDE1_STC_INVALIDTRANSPORTCORRELATOR"],
   '1DE0004E' => ["address not accessible","KDE1_STC_ADDRESSINACCESSIBLE"],
   '1DE0004F' => ["secure endpoint unavailable","KDE1_STC_SECUREENDPOINTUNAVAILABLE"],
   '1DE00050' => ["ipv6 support unavailable","KDE1_STC_IPV6UNAVAILABLE"],
   '1DE00051' => ["z/OS TTLS support not available","KDE1_STC_TTLSUNAVAILABLE"],
   '1DE00052' => ["z/OS TTLS connection not established","KDE1_STC_TTLSNOTESTABLISHED"],
   '1DE00053' => ["z/OS TTLS connection policy not application controlled","KDE1_STC_TTLSNOTAPPCTRL"],
   '1DE00054' => ["Send request was incomplete","KDE1_STC_INCOMPLETESEND"],
   '1DE00055' => ["operating in originate-only ephemeral mode","KDE1_STC_ORIGONLYEPHMODE"],
   '1DE00056' => ["socket file descriptor out of range of select mask size","KDE1_STC_SOCKETFDTOOLARGE"],
   '1DE00057' => ["unable to create object of type pthread_mutex_t","KDE1_STC_MUTEXERROR"],
   '1DE00058' => ["unable to create object of type pthread_cond_t","KDE1_STC_CONDITIONERROR"],
   '1DE00059' => ["gateway element must have a name attribute","KDE1_STC_GATEWAYNAMEREQUIRED"],
   '1DE0005A' => ["gateway name already in use","KDE1_STC_GATEWAYNAMEEXISTS"],
   '1DE0005B' => ["invalid numeric attribute","KDE1_STC_XMLATTRNONNUMERIC"],
   '1DE0005C' => ["numeric attribute value out of range","KDE1_STC_XMLATTROUTOFRANGE"],
   '1DE0005D' => ["required attribute not supplied","KDE1_STC_XMLATTRREQUIRED"],
   '1DE0005E' => ["attribute keyword not recognized","KDE1_STC_XMLATTRKEYWORDINVALID"],
   '1DE0005F' => ["attribute keyword is ambiguous","KDE1_STC_XMLATTRKEYWORDAMBIG"],
   '1DE00060' => ["gateway configuration file not found","KDE1_STC_GATEWAYCONFIGFILENOTFOUND"],
   '1DE00061' => ["syntax error in XML document","KDE1_STC_XMLDOCUMENTERROR"],
   '1DE00062' => ["listening bindings require an endpoint number","KDE1_STC_ENDPOINTREQUIRED"],
   '1DE00063' => ["thread creation procedure failed","KDE1_STC_CREATETHREADFAILED"],
   '1DE00064' => ["nested downstream definitions not supported","KDE1_STC_DOWNSTREAMNESTING"],
   '1DE00065' => ["upstream interfaces require one or more downstream interfaces","KDE1_STC_NODOWNSTREAMINTERFACES"],
   '1DE00066' => ["invalid socket option","KDE1_STC_SOCKETOPTIONINVALID"],
   '1DE00067' => ["Windows event object error","KDE1_STC_WSAEVENTERROR"],
   '1DE00068' => ["simultaneous per socket wait limit exceeded","KDE1_STC_TOOMANYWAITS"],
   '1DE00069' => ["XML document did not contain TEP gateway configuration","KDE1_STC_NOGATEWAYDEFINITIONS"],
   '1DE0006A' => ["Socket monitor handle invalid","KDE1_STC_MONITORHANDLEINVALID"],
   '1DE0006B' => ["Connection limit reached","KDE1_STC_CONNECTIONLIMITREACHED"],
   '1DE0006C' => ["Gateway contains no zone elements","KDE1_STC_NOZONESINGATEWAY"],
   '1DE0006D' => ["Zone contains no interface elements","KDE1_STC_NOINTERFACESINZONE"],
   '1DE0006E' => ["Connection ID invalid","KDE1_STC_BADCONNECTIONID"],
   '1DE0006F' => ["Service name invalid","KDE1_STC_BADSERVICENAME"],
   '1DE00070' => ["Pipe handle invalid","KDE1_STC_BADPIPEHANDLE"],
   '1DE00071' => ["Connection markup is required","KDE1_STC_NEEDCONNECTIONTAG"],
   '1DE00072' => ["Monitor close in progress","KDE1_STC_MONITORCLOSING"],
   '1DE00073' => ["Socket not detached from monitor","KDE1_STC_MONITORDETACHERROR"],
   '1DE00074' => ["datastream integrity lost","KDE1_STC_DATASTREAMINTEGRITYLOST"],
   '1DE00075' => ["retry limit exceeded","KDE1_STC_RETRYLIMITEXCEEDED"],
   '1DE00076' => ["pipe not in required state","KDE1_STC_WRONGPIPESTATE"],
   '1DE00077' => ["Local binding is not unique","KDE1_STC_DUPLICATELOCALBINDING"],
   '1DE00078' => ["PIPE packet header missing or invalid","KDE1_STC_PACKETHEADERINVALID"],
   '1DE00079' => ["XML element inconsistency","KDE1_STC_XMLELEMENTINCONSISTENCY"],
   '1DE0007A' => ["Endpoint security negotiation failed","KDE1_STC_ENDPOINTNOTSECURE"],
   '1DE0007B' => ["file descriptor limit reached","KDE1_STC_FILEDESCRIPTORSEXHAUSTED"],
   '1DE0007C' => ["invalid link handle","KDE1_STC_BADLINKHANDLE"],
   '1DE0007D' => ["expired link handle","KDE1_STC_EXPIREDLINKHANDLE"],
   '1DE0007E' => ["RFC1831 record not complete","KDE1_STC_REPLYRECORDSPLIT"],
   '1DE0007F' => ["RFC1831 record too long","KDE1_STC_REPLYTOOLONG"],
   '1DE00080' => ["RFC1831 stream contains extra data","KDE1_STC_REPLYSTREAMERROR"],
   '1DE00081' => ["RFC1831 reply expected","KDE1_STC_REPLYEXPECTED"],
   '1DE00082' => ["RFC1831 request not accepted","KDE1_STC_REMOTEREQUESTREJECTED"],
   '1DE00083' => ["RFC1831 request failed","KDE1_STC_REMOTEREQUESTFAILED"],
   '1DE00084' => ["RFC1833 portmap request error","KDE1_STC_PORTMAPREQUESTERROR"],
              );

my %commenvx = (
                 'CT_CMSLIST' => 1,
                 'CTIRA_RECONNECT_WAIT' => 1,
                 'CTIRA_MAX_RECONNECT_TRIES' => 1,
                 'KDE_TRANSPORT' => 1,
                 'CTIRA_PRIMARY_FALLBACK_INTERVAL' => 1,
                 'KDEB_INTERFACELIST_IPV6' => 1,
                 'KDEB_INTERFACELIST' => 1,
                 'CTIRA_HEARTBEAT' => 1,
              );

my %porterrx;

my $rptkey;


my %hsitdata;                                # hash of situation name to pure/sampled

my %flowtems;                                # track flow of Agent to TEMS
my $flowkey;                                 # usually timestamp of start
my $flow_ref;                                #
my %flowrate;                                # accumulate flow rates by second


my $sit_start = 0;                           # first expired time
my $sit_end = 0;                             # last expired time
my $sit_duration = 0;                        # total expired time


my $isitname;                                # incoming situation name
my $iobjid;                                  # incoming object id nnnnnnnn,nnnnnnnnn
my $itable;                                  # incoming table
my $ithread;                                 # incoming thread
my $isittype;                                # type of sit 1=sampled, 4=pure
my $itaken;                                  # calculated seconds for sample time
my $irowsize;                                # size of rows
my $inext;                                   # time for next evaluation
my $srows;                                   # number of rows sent

my $sitseq = -1;                             # unique sit identifier

my $kx;
my %sitrun = ();                             # hash of current running situation data
my %sitpure = ();                            # hash of observed pure situations running
my $pure_start = 0;
my $pure_end = 0;
my $pure_dur = 0;
my %thrun = ();                              # index from thread to current capture hash
my %tabsize = ();                            # record size of attribute table
my $sitref;

my $histruni = -1;                           # count of history records
my @histrun = ();                            # history of situation completions - when stopped

my %sit_details = ();                        # what situations with detailed output


my %advrptx = ();

my $cnt = -1;
my @oline = ();
my $hdri = -1;                               # some header lines for report
my @hdr = ();                                #
my $advisori = -1;
my @advisor = ();
my %timelinex;
my $timeline_start;
my %timelinexx;
my %envx;
my %rpcrunx;
my @dlogfiles;
my @seg = ();
my @seg_time = ();
my $segi = -1;
my $segp = -1;
my $segcur = "";
my $segline;
my $segmax = 0;



#  following are the nominal values. These are used to generate an advisories section
#  that can guide usage of the Workload report. These can be overridden by the agentaud.ini file.

my $opt_nohdr;                               # when 1 no headers printed
my $opt_objid;                               # when 1 print object id
my $opt_o;                                   # when defined filename of report file
my $opt_tsit;                                # when defined debug testing sit
my $opt_slot;                                # when defined specify history slots, default 60 minutes
my $opt_allports = 1;
my $opt_pc;
my $opt_allenv;                              # when 1 dump all environment variables
my $opt_allinv;                              # when 1 dump all environment variables
my $opt_merge;

my $arg_start = join(" ",@ARGV);
$hdri++;$hdr[$hdri] = "Runtime parameters: $arg_start";

while (@ARGV) {
   if ($ARGV[0] eq "-h") {
      &GiveHelp;                        # print help and exit
   }
   if ($ARGV[0] eq "-z") {
      $opt_z = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-cmdall") {
      $opt_cmdall = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-nohdr") {
      $opt_nohdr = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-objid") {
      $opt_objid = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-tsit") {
      shift(@ARGV);
      $opt_tsit = shift(@ARGV);
      die "Option -tsit with no test situation set" if !defined $opt_tsit;
   } elsif ($ARGV[0] eq "-pc") {
      shift(@ARGV);
      $opt_pc = shift(@ARGV);
      die "Option -pc with no product code set" if !defined $opt_pc;
   } elsif ($ARGV[0] eq "-o") {
      shift(@ARGV);
      if (defined $ARGV[0]) {
         if (substr($ARGV[0],0,1) ne "-") {
            $opt_o = shift(@ARGV);
         }
      }
   } elsif ($ARGV[0] eq "-zop") {
      shift(@ARGV);
      $opt_zop = shift(@ARGV);
      die "-zop output specified but no file found\n" if !defined $opt_zop;
   } elsif ($ARGV[0] eq "-sit") {
      shift(@ARGV);
      my $detone = shift(@ARGV);
      die "sit specified but no situation found found\n" if !defined $detone;
      die "sit specified but option found next\n" if substr($detone,0,1) eq "-";
      my %sithist = ();                # template empty hash to hold detailed data per situation
      $sit_details{$detone} = \%sithist;
   } elsif ($ARGV[0] eq "-slot") {
      shift(@ARGV);
      $opt_slot = shift(@ARGV);
      die "slot specified but no slot time found\n" if !defined $opt_slot;
      die "slot must be an integer 1 to 60 minutes" if ($opt_slot < 1) or ($opt_slot > 60);
   } elsif ($ARGV[0] eq "-v") {
      $opt_v = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-allenv") {
      $opt_allenv = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-allinv") {
      $opt_allinv = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-vv") {
      $opt_vv = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-logpath") {
      shift(@ARGV);
      $opt_logpath = shift(@ARGV);
      die "logpath specified but no path found\n" if !defined $opt_logpath;
   } else {
      $logfn = shift(@ARGV);
      die "log file name not defined\n" if !defined $logfn;
   }
}


die "logpath and -z must not be supplied together\n" if defined $opt_z and defined $opt_logpath;

if (!defined $opt_logpath) {$opt_logpath = "";}
if (!defined $logfn) {$logfn = "";}
if (!defined $opt_z) {$opt_z = 0;}
if (!defined $opt_zop) {$opt_zop = ""}
if (!defined $opt_cmdall) {$opt_cmdall = 0;}
if (!defined $opt_nohdr) {$opt_nohdr = 0;}
if (!defined $opt_objid) {$opt_objid = 0;}
if (!defined $opt_tsit) {$opt_tsit = "ZZZZZZZZZ";}
if (!defined $opt_o) {$opt_o = "agentaud.csv";}
if (!defined $opt_slot) {$opt_slot = 60;}
if (!defined $opt_v) {$opt_v = 0;}
if (!defined $opt_allenv) {$opt_allenv = 0;}
if (!defined $opt_allinv) {$opt_allinv = 0;}
if (!defined $opt_allinv) {$opt_allinv = 0;}
if (!defined $opt_vv) {$opt_vv = 0;}
if (!defined $opt_pc) {$opt_pc = "";}
$opt_merge = $opt_allinv;

open( ZOP, ">$opt_zop" ) or die "Cannot open zop file $opt_zop : $!" if $opt_zop ne "";

if ($gWin == 1) {
   $pwd = `cd`;
   chomp($pwd);
   if ($opt_logpath eq "") {
      $opt_logpath = $pwd;
   }
   $opt_logpath = `cd $opt_logpath & cd`;
   chomp($opt_logpath);
   chdir $pwd;
} else {
   $pwd = `pwd`;
   chomp($pwd);
   if ($opt_logpath eq "") {
      $opt_logpath = $pwd;
   } else {
      $opt_logpath = `(cd $opt_logpath && pwd)`;
      chomp($opt_logpath);
   }
   chdir $pwd;
}


$opt_logpath .= '/';
$opt_logpath =~ s/\\/\//g;    # switch to forward slashes, less confusing when programming both environments

die "logpath or logfn must be supplied\n" if !defined $logfn and !defined $opt_logpath;

# Establish nominal values for the Advice Summary section

my $pattern;
my @results = ();
my $loginv;
my $inline;
my $logbase;
my %todo = ();     # associative array of names and first identified timestamp
my $skipzero = 0;
my $key;


if ($logfn eq "") {
$DB::single=2;
   $pattern = "_ms(_kdsmain)?\.inv";
#   $pattern = "_" . $opt_pc . "_k" . $opt_pc . "agent\.inv" if $opt_pc ne "";
   $pattern = "_k" . $opt_pc . "agent\.inv" if $opt_pc ne "";
   $pattern = "_" . $opt_pc . "_k" . $opt_pc . "cma\.inv" if $opt_pc eq "nt";
   @results = ();
   opendir(DIR,$opt_logpath) || die("cannot opendir $opt_logpath: $!\n"); # get list of files
   @results = grep {/$pattern/} readdir(DIR);
$DB::single=2;
   closedir(DIR);
   die "No _*.inv found\n" if $#results == -1;
   $logfn =  $results[0];
   if ($#results > 0) {         # more than one inv file - determine which one has most recent date
      my $last_modify = 0;
      $logfn =  $results[0];
      for my $r (@results) {
         my $testpath = $opt_logpath . $r;
         my $modify = (stat($testpath))[9];
         if ($last_modify == 0) {
            $logfn = $r;
            $last_modify = $modify;
            next;
         }
         next if $modify < $last_modify;
         $logfn = $r;
         $last_modify = $modify;
      }
   }
}

my %logbasex;
$full_logfn = $opt_logpath . $logfn;
if ($logfn =~ /.*\.inv$/) {
   open(INV, "< $full_logfn") || die("Could not open inv  $full_logfn\n");
   my @inv = <INV>;
   close(INV);
   my $l = 0;
   die "empty INV file $full_logfn\n" if $#inv == -1;
   foreach my $inline (@inv) {
      $inline =~ s/\\/\//g;    # switch to forward slashes, less confusing when programming both environments
      $pos = rindex($inline,'/');
      $inline = substr($inline,$pos+1);
      $inline =~ m/(.*)-\d\d\.log$/;
      $inline =~ m/(.*)-\d\.log$/ if !defined $1;
      die "invalid log form $inline from $full_logfn line $l\n" if !defined $1;
      $logbase = $1;
      $logfn = $1 . '-*.log';
      $logbasex{$logbase} = 1;
      last if $opt_allinv == 0;
   }
}


if (!defined $logbase) {
   $logbasex{$logfn} = 1 if ! -e $logfn;
my $x = 1;
}

sub open_kib;
sub close_kib;
sub read_kib;

my $ll = 0;
foreach my $log (keys %logbasex) {
   $ll += 1;
   $logbase = $log;
   do_rpt;
my $x = 1;
}

if ($opt_merge == 1) {
   my $mfn = "merge.csv";
   open MH, ">$mfn" or die "can't open $mfn: $!";
   foreach $f ( sort { $a cmp $b} keys %timelinexx) {
      my $ml_ref = $timelinexx{$f};
      $outl = sec2ltime($ml_ref->{time}+$local_diff) . ",";
      $outl .= $ml_ref->{hextime} . ",";
      $outl .= $ml_ref->{l} . ",";
      $outl .= $ml_ref->{advisory} . ",";
      $outl .= $ml_ref->{notes} . ",";
      $outl .= $ml_ref->{logbase} . ",";
      print MH "$outl\n";
   }
   close MH;
}

exit 0;


sub do_rpt {

   $cnt = -1;
   @oline = ();
   $hdri = -1;                               # some header lines for report
   @hdr = ();                                #
   $advisori = -1;
   @advisor = ();
   %timelinex = ();
   $timeline_start = 0;
   %envx = ();
   %rpcrunx = ();
   @dlogfiles = [];
   @seg = ();
   @seg_time = ();
   $segi = -1;
   $segp = -1;
   $segcur = "";
   $segline = "";
   $segmax = 0;
   %todo = ();

   $hdri++;$hdr[$hdri] = "TEMA Workload Advisory report v$gVersion";
   my $audit_start_time = gettime();       # formated current time for report
   $hdri++;$hdr[$hdri] = "Start: $audit_start_time";

   my $pos;

   open_kib();

   $l = 0;

   my $locus;                  # (4D81D81A.0000-A1A:kpxrpcrq.cpp,749,"IRA_NCS_Sample")
   my $rest;                   # unprocesed data
   my $logtime;                # distributed time stamp in seconds - number of seconds since Jan 1, 1970
   my $logtimehex;             # distributed time stamp in hex
   my $logline;                # line number within $logtimehex
   my $logthread;              # thread information - prefixed with "T"
   my $logunit;                # where printed from - kpxrpcrq.cpp,749
   my $logentry;               # function printed from - IRA_NCS_Sample
   my $irows;                  # number of rows
   my $isize;                  # size of rows
   my $itbl;                   # table name involved
   my $siti = -1;              # count of situations
   my @sit = ();               # situation name
   my %sitx = ();              # associative array from situation name to index
   my @sitct = ();             # situation results count
   my @sitrows = ();           # situation results count of rows
   my @sitres = ();            # situation results count of result size
   my @sittbl = ();            # situation table
   my @sitrmin = ();           # situation results minimum of result size
   my @sitrmax = ();           # situation results maximum of result size
   my @sitrmaxnode = ();       # situation node giving maximum of result size
   my $sitct_tot = 0;          # total results
   my $sitrows_tot = 0;        # total rows
   my $sitres_tot = 0;         # total size
   my $trcstime = 0;           # trace smallest time seen - distributed
   my $trcetime = 0;           # trace largest time seen  - distributed
   my $timestart = "";         # first time seen - z/OS
   my $timeend = "";           # last time seen - z/OS
   my $sx;                     # index
   my $insize;                 # calculated
   my $csvdata;
   my @words;

   my @man = ();               # managed system name
   my %manx = ();              # associative array from managed system name to index
   my @manct = ();             # managed system results count
   my @manrows = ();           # managed system results count of rows
   my @manres = ();            # managed system results count of result size
   my @mantbl = ();            # managed system table
   my @manrmin = ();           # managed system results minimum of result size
   my @manrmax = ();           # managed system results maximum of result size
   my @manrmaxsit = ();        # managed system situation giving maximum of result size
   my $mx;                     # index



   my @pt  = ();               # pt keys - table_path
   my %ptx = ();               # associative array from from pt key to index
   my @pt_table = ();          # pt table
   my @pt_path = ();           # pt path
   my @pt_insert_ct = ();      # Count of insert
   my @pt_query_ct = ();       # Count of query
   my @pt_select_ct = ();      # Count of select
   my @pt_selectpre_ct = ();   # Count of select prefiltered
   my @pt_delete_ct = ();      # Count of delete
   my @pt_total_ct = ();       # Total Count
   my @pt_error_ct = ();       # error count
   my @pt_errors   = ();       # string of different error status types
   my $pt_etime = 0;
   my $pt_stime = 0;
   my $pt_dur   = 0;
   my $pt_total_total = 0;



   # Summarized action command captures
   my $acti = -1;                               # Action command count
   my @act = ();                                # array of action commands - down to first blank
   my %actx = ();                               # index from action command
   my @act_elapsed = ();                        # total elapsed time of action commands
   my @act_ok = ();                             # count when exit status was zero
   my @act_err = ();                            # count when exit status was non-zero
   my @act_ct = ();                             # count of total action commands
   my @act_act = ();                            # array of action commands
   my $act_id = -1;                             # sequence id for action commands
   my $act_max = 0;                             # max number of simultaneous action commands
   my @act_max_cmds = ();                       # array of max simultaneous action commands
   my %act_current_cmds = ();                   # hash of current simultaneous action commands

   my $act_start = 0;
   my $act_end = 0;

   # running action command captures.
   # used during capture of data
   my %runx = ();                               # index of running capture threads using Tthread
   my %contx = ();                              # index from cont to same array using hextime.line
   my $contkey;

   # following are in the $runx value, which is actually an array
   my $runref;                                  # reference to array
   my $run_thread;                              # needed for cross references

   my $inrowsize;
   my $inobject;
   my $intable;
   my $inrows;
   my $inreadct;
   my $inskipct;
   my $inwritect;

   my %table_rowsize = ();

   my $histcnt = 0;
   my $total_histrows = 0;
   my $total_histsecs = 0;


   my $hist_sec;
   my $hist_min;
   my $hist_hour;
   my $hist_day;
   my $hist_month;
   my $hist_year;

   my $hist_min_time = 0;
   my $hist_max_time = 0;
   my $hist_elapsed_time = 0;

   my %histobjx = ();
   my $inmetatable;
   my $inmetaobject;

   my $histi = -1;             # historical data export total, key by object name
   my $hx;
   my @hist = ();                  # object name - attribute group
   my %histx = ();                 # index to object name
   my @hist_table = ();            # table name
   my @hist_appl = ();             # application name
   my @hist_rows = ();             # number of rows
   my @hist_rowsize = ();          # size of row
   my @hist_bytes = ();            # total size of rows
   my @hist_maxrows = ();          # maximum rows at end of cycle
   my @hist_minrows = ();          # minimum rows at end of cycle
   my @hist_totrows = ();          # Total rows at end of cycle
   my @hist_lastrows = ();         # last rows at end of cycle
   my @hist_cycles = ();           # total number of export cyclces

   my $histtimei = -1;             # historical data export hourly, yymmddhh
   my @histtime = ();              # key yymmddhh
   my %histtimex = ();             # index to yymmddhh
   my @histtime_rows = ();         # number of rows
   my @histtime_bytes = ();        # total size of rows
   my @histtime_min_time = ();     # minimum epcoh time
   my @histtime_max_time = ();     # maximum epcoh time

   my $histobjecti = -1;           # historical data export hourly, object_yymmddhh
   my @histobject = ();            # key object_yymmddhh

   my %histobjectx = ();           # index to object_yymmddhh
   my @histobject_object = ();     # object name
   my @histobject_time = ();       # time
   my @histobject_table = ();      # table name
   my @histobject_appl = ();       # application name
   my @histobject_rows = ();       # number of rows
   my @histobject_rowsize = ();    # size of rows
   my @histobject_bytes = ();      # total size of rows

   my $trace_ct = 0;               # count of trace lines
   my $trace_sz = 0;               # total size of trace lines


   my $state = 0;       # 0=look for offset, 1=look for zos initial record, 2=look for zos continuation, 3=distributed log
   my $partline = "";          # partial line for z/OS RKLVLOG
   my $dateline = "";          # date portion of timestamp
   my $timeline = "";          # time portion of timestamp
   my $offset = 0;             # track sysout print versus disk flavor of RKLVLOG
   my $totsecs = 0;            # added to when time boundary crossed
   my $outl;

   my $total_sendq = 0;
   my $total_recvq = 0;
   my $max_sendq = 0;
   my $max_recvq = 0;


   my %epoch = ();             # convert year/day of year to Unix epoch seconds
   my $yyddd;
   my $yy;
   my $ddd;
   my $days;
   my $saveline;
   my $oplogid;

   my $lagline;
   my $lagopline;
   my $lagtime;
   my $laglocus;

   if ($opt_z == 1) {$state = 1}

   $inrowsize = 0;

   for(;;)
   {
      read_kib();
      if (!defined $inline) {
         close_kib();
         last;
      }
      $l++;
      if ($l%10000 == 0) {
         print STDERR "Working on $l\n" if $opt_vv == 1;
      }
   # following two lines are used to debug errors. First you flood the
   # output with the working on log lines, while merging stdout and stderr
   # with  1>xxx 2>&1. From that you determine what the line number was
   # before the faulting processing. Next you turn that off and set the conditional
   # test for debugging and test away.
   # print STDERR "working on log $segcurr at $l\n";

      chomp($inline);
      if ($opt_z == 1) {
         if (length($inline) > 132) {
            $inline = substr($inline,0,132);
         }
         next if length($inline) <= 21;
      }
      if (($segmax == 0) or ($segp > 0)) {
         if ($skipzero == 0) {
            $trace_ct += 1;
            $trace_sz += length($inline);
         }
      }
      if ($state == 0) {                       # state = 0 distributed log - no filtering - following is pure z logic
         $oneline = $inline;
      }
      elsif ($state == 1) {                       # state 1 - detect print or disk version of sysout file
         $offset = (substr($inline,0,1) eq "1") || (substr($inline,0,1) eq " ");
         $state = 2;
         $lagopline = 0;
         $lagtime = 0;
         $laglocus = "";
         next;
      }
      elsif ($state == 2) {                    # state 2 = look for part one of target lines
         next if length($inline) < 36;
         next if substr($inline,21+$offset,1) ne '(';
         next if substr($inline,26+$offset,1) ne '-';
         next if substr($inline,35+$offset,1) ne ':';
         next if substr($inline,0+$offset,2) != '20';

         # convert the yyyy.ddd hh:mm:ss:hh stamp into the epoch seconds form.
         # The goal is to allow a common logic for z/OS and distributed logs.

         # for year/month/day calculation is this:
         #   if ($mo > 2) { $mo++ } else {$mo +=13;$yy--;}
         #   $day=($yy*365)+int($yy/4)-int($yy/100)+int($yy/400)+int($mo*306001/10000)+$dd;
         #   $days_since_epoch=$day-719591; # (which is Jan 1 1970)
         #
         # In this case we need the epoch days for begining of Jan 1 of current year and then add day of year
         # Use an associative array part so the day calculation only happens once a day.
         # The result is normalized to UTC 0 time [like GMT] but is fine for duration calculations.

         $yyddd = substr($inline,0+$offset,8);
         $timeline = substr($inline,9+$offset,11);
         if (!defined $epoch{$yyddd}){
            $yy = substr($yyddd,0,4);
            $ddd = substr($yyddd,5,3);
            $yy--;
            $days=($yy*365)+int($yy/4)-int($yy/100)+int($yy/400)+int(14*306001/10000)+$ddd;
            $epoch{$yyddd} = $days-719591;
         }
         $lagtime = $epoch{$yyddd}*86400 + substr($timeline,0,2)*3600 + substr($timeline,3,2)*60 + substr($timeline,6,2);
         $lagline = substr($inline,21+$offset);
         $lagline =~ /^\((.*?)\)/;
         $laglocus = "(" . $1 . ")";
         $state = 3;
         next;
      }

      # continuation is without a locus
      elsif ($state == 3) {                    # state 3 = potentially collect second part of line
         # case 1 - look for the + sign which means a second line of trace output
         #   emit data and resume looking for more
         if (substr($inline,21+$offset,1) eq "+") {
            next if $lagline eq "";
            $oneline = $lagline;
            $logtime = $lagtime;
            $lagline = $inline;
            $lagtime = $lagtime;
            $laglocus = "";
            $state = 3;
            # fall through and process $oneline
         }

         # case 3 - line too short for a locus
         #          Append data to lagline and move on
         elsif (length($inline) < 35 + $offset) {
            $lagline .= " " . substr($inline,21+$offset);
            $state = 3;
            next;
         }

         # case 4 - line has an apparent locus, emit laggine line
         #          and continue looking for data to append to this new line
         elsif ((substr($inline,21+$offset,1) eq '(') &&
                (substr($inline,26+$offset,1) eq '-') &&
                (substr($inline,35+$offset,1) eq ':') &&
                (substr($inline,0+$offset,2) eq '20')) {
            if ($lagopline == 1) {
               if ($opt_zop ne "") {
                  print ZOP "$lagline\n";
               }
               $lagopline = 0;
            }
            $oneline = $lagline;
            $logtime = $lagtime;
            $yyddd = substr($inline,0+$offset,8);
            $timeline = substr($inline,9+$offset,11);
            if (!defined $epoch{$yyddd}){
               $yy = substr($yyddd,0,4);
               $ddd = substr($yyddd,5,3);
               $yy--;
               $days=($yy*365)+int($yy/4)-int($yy/100)+int($yy/400)+int(14*306001/10000)+$ddd;
              $epoch{$yyddd} = $days-719591;

            }
            $lagtime = $epoch{$yyddd}*86400 + substr($timeline,0,2)*3600 + substr($timeline,3,2)*60 + substr($timeline,6,2);
            $lagline = substr($inline,21+$offset);
            $lagline =~ /^\((.*?)\)/;
            $laglocus = "(" . $1 . ")";
            $state = 3;
            # fall through and process $oneline
         }

         # case 5 - Identify and ignore lines which appear to be z/OS operations log entries
         else {
            $oplogid = substr($inline,21+$offset,7);
            $oplogid =~ s/\s+$//;
            if ((substr($oplogid,0,3) eq "OM2") or
                (substr($oplogid,0,1) eq "K") or
                (substr($oplogid,0,1) eq "O")) {
               if ($lagopline == 1) {
                  if ($opt_zop ne "") {
                     print ZOP "$lagline\n";
                  }
               }
                $lagopline = 1;
                $lagline = substr($inline,$offset);
            } else {
                $lagline .= substr($inline,21+$offset);
            }
            $state = 3;
            next;
         }
      }
      else {                   # should never happen
         print STDERR $oneline . "\n";
         die "Unknown state [$state] working on log $logfn at $l\n";
         next;
      }

      if ($start_date eq "") {
         if (substr($oneline,0,1) eq "+") {
            if (index($oneline,"Start Date:") != -1) {
               $oneline =~ /Start Date: (\d{4}\/\d{2}\/\d{2})/;
               $start_date = $1 if defined $1;
            }
         }
      }
      if ($start_time eq "") {
         if (substr($oneline,0,1) eq "+") {
            if (index($oneline,"Start Time:") != -1) {
               $oneline =~ /Start Time: (\d{2}:\d{2}:\d{2})/;
               $start_time = $1 if defined $1;
            }
         }
       }

       #(5AA2E31C.0000-7E4:kdcc1sr.c,642,"rpc__sar") Remote call failure: 1C010001
       #+5AA2E31C.0000   activity: 11f0f9725f90.42.02.ac.13.80.05.06.94   started: 5AA2E196
       #+5AA2E31C.0000  interface: 6f21c4ad7f33.02.c6.d2.23.0c.00.00.00   version: 131
       #+5AA2E31C.0000     object: 5e3d67a8d345.02.81.00.e7.48.00.00.00     opnum: 2
       #+5AA2E31C.0000  srvr-boot: 5A791892        length: 1058         a/i-hints: FFA5/000D
       #+5AA2E31C.0000   sent-req: true         sent-last: true              idem: false
       #+5AA2E31C.0000      maybe: false            large: true          callback: false
       #+5AA2E31C.0000  snd-frags: false        rcv-frags: false            fault: false
       #+5AA2E31C.0000     reject: false          pkts-in: 8             pkts-bad: 0
       #+5AA2E31C.0000    pkts-cb: 0            pkts-wact: 0            pkts-oseq: 8
       #+5AA2E31C.0000    pkts-ok: 0             duration: 390              state: 1
       #+5AA2E31C.0000   interval: 30             retries: 0                pings: 12
       #+5AA2E31C.0000   no-calls: 0              working: 0                facks: 0
       #+5AA2E31C.0000      waits: 14            timeouts: 13            sequence: 506
       #+5AA2E31C.0000     b-size: 32              b-fail: 0               b-hist: 0
       #+5AA2E31C.0000   nextfrag: 2              fragnum: 0
       #+5AA2E31C.0000     w-secs: 390             f-secs: 360             l-secs: 900
       #+5AA2E31C.0000     e-secs: 0                  mtu: 944         KDE1_stc_t: 1DE0000F
       #+5AA2E31C.0000   bld-date: Mar 27 2013   bld-time: 13:15:55      revision: D140831.1:1.1.1.13
       #+5AA2E31C.0000        bsn: 4323373            bsq: 5               driver: tms_ctbs623fp3:d3086a
       #+5AA2E31C.0000      short: 10             contact: 180              reply: 300
       #+5AA2E31C.0000    req-int: 30            frag-int: 30            ping-int: 30
       #+5AA2E31C.0000      limit: 900         work-allow: 60
       #+5AA2E31C.0000  loc-endpt: ip.spipe:#*:7759
       #+5AA2E31C.0000  rmt-endpt: ip.spipe:#146.89.140.75:3660
       if (substr($oneline,0,1) eq "+") {
          if (defined $logthread) {
             my $rpc_ref = $rpcrunx{$logthread};
             if (defined $rpc_ref) {
               my $pline = substr($oneline,15);  #   srvr-boot: 5A791892        length: 1058         a/i-hints: FFA5/000D
               $pline =~ s/^\s+|\s+$//;     # strip leading/trailing white space
               $pline =~ s/: /:/g;
               @segs = split("[ ]{2,99}",$pline);
               my $iattr = "";
               my $ivalue = "";
               foreach my $f (@segs) {
                  $f =~  s/^\s+|\s+$//;     # strip leading/trailing white space
                  my @parts = split(":(?!#)",$f);
                  $iattr = $parts[0];
                  $ivalue = $parts[1];
                  $iattr =~ s/^\s+|\s+$//;     # strip leading/trailing white space
                  $ivalue =~ s/^\s+|\s+$//;     # strip leading/trailing white space
                  $rpc_ref->{$iattr} = $ivalue;
               }
               if ($iattr eq "rmt-endpt") {
                  my $istarted = $rpc_ref->{started};
                  my $lstarted = sec2ltime(hex($rpc_ref->{started})+$local_diff);
                  my $inotes = "started[$lstarted] ";
                  $inotes .= 'loc-endpt' . "[$rpc_ref->{'loc-endpt'}] ";
                  $inotes .= 'rmt-endpt' . "[$rpc_ref->{'rmt-endpt'}] ";
                  $inotes .= "mtu[$rpc_ref->{mtu}] ";
                  $inotes .= "timeouts[$rpc_ref->{timeouts}] ";
                  my @msg_ref = $kdemsgx{$rpc_ref->{KDE1_stc_t}};
                  my $msg_txt = $msg_ref[0][1] . " \"" . $msg_ref[0][0] . "\"";
                  $inotes .= "KDE1_stc_t[$rpc_ref->{KDE1_stc_t} $msg_txt]";
                  set_timeline($logtime,$l,$logtimehex,2,"RPC-Fail",$inotes);
                  delete $rpcrunx{$logthread};
               }
             }
          }
       }




      # Agent workload flow
      # structures
      # running sits
      #   key is sitname_objectid
      #    sitname
      #    objectid
      #    state
      #    data collection count
      #    data collection rows
      #    data collection filtered rows
      #    rows sent to TEMS
      #    size of rows
      #    collection time
      #    delay from collection time to filter complete
      #    delay from filter time to send TEMS time
      #    Thread_key
      #
      # thread index
      #    sitname_objectid
      #
      # History - for each completed situation instance
      #    simple array of running sit hashes
      #
      # (53FE31BA.0045-61C:kglhc1c.c,601,"KGLHC1_Command") <0x190B4CFB,0x8A> Command String
      # +53FE31BA.0045     00000000   443A5C73 63726970  745C756E 69782031   D:\script\unix.1
      # +53FE31BA.0045     00000010   31343038 32373134  31353038 30303020   140827141508000.


      if (substr($oneline,0,1) eq "+")  {
         $contkey = substr($oneline,1,13);
         $runref = $contx{$contkey};
         if (defined $runref) {
            if ($runref->{'state'} == 3) {
               my $cmd_frag = substr($oneline,30,36);
               $cmd_frag =~ s/\ //g;
               $cmd_frag =~ s/(([0-9a-f][0-9a-f])+)/pack('H*', $1)/ie;
               $runref->{'cmd'} .= $cmd_frag;
            }
         }
      }
      if (substr($oneline,0,1) ne "(") {next;}
      $oneline =~ /^(\S+).*$/;          # extract locus part of line
      $locus = $1;
      if ($opt_z == 0) {                # distributed has five pieces
         $locus =~ /\((.*)\.(.*)-(.*):(.*)\,\"(.*)\"\)/;
         next if index($1,"(") != -1;   # ignore weird case with embedded (
         $logtime = hex($1);            # decimal epoch
         $logtimehex = $1;              # hex epoch
         $logline = $2;                 # line number following hex epoch, meaningful with there are + extended lines
         $logthread = "T" . $3;         # Thread key
         $logunit = $4;                 # source unit and line number
         $logentry = $5;                # function name
      }
      else {                            # z/OS has three pieces
         $locus =~ /\((.*)-(.*):(.*),\"(.*)\"\)/;
         $logline = 0;      ##???
         $logthread = "T" . $2;
         $logunit = $3;
         $logentry = $4;
      }
      # following calculates difference between diagnostic log
      # time and the local time as recorded in RAS1 header lines
      if ($local_diff == -1) {
         if ($start_time ne "") {
            if ($start_date ne "") {
               my $iyear = substr($start_date,0,4) - 1900;
               my $imonth = substr($start_date,5,2) - 1;
               my $iday = substr($start_date,8,2);
               my $ihour = substr($start_time,0,2);
               my $imin = substr($start_time,3,2);
               my $isec = substr($start_time,6,2);
               my $ltime = timelocal($isec,$imin,$ihour,$iday,$imonth,$iyear);
               $local_diff = $ltime - $logtime;
            }
         }
      }
      if ($skipzero == 0) {
         if (($segmax <= 1) or ($segp > 0)) {
            if ($trcstime == 0) {
               $trcstime = $logtime;
               $trcetime = $logtime;
            }
            if ($logtime < $trcstime) {
               $trcstime = $logtime;
            }
            if ($logtime > $trcetime) {
               $trcetime = $logtime;
            }
         }
      }
      set_timeline($logtime,$l,$logtimehex,-1,"Log","Start") if $timeline_start == 0;
      $timeline_start = 1;

      #(5A9E41FE.0088-7BC:kraarreg.cpp,1075,"ConnectToProxy") Successfully connected to CMS REMOTE_usrdrtm041ccpr2 using ip.spipe:#146.89.140.75[3660]
      #(5AA2E3F5.000A-9F0:kraarreg.cpp,2907,"PrimaryTEMSperiodicLookupThread") Primary TEMS <IP.SPIPE:146.89.140.75> Current connected TEMS <146.89.140.76>
      #(5AA2E3F4.0001-13E0:kraarreg.cpp,1781,"LookupAndRegisterWithProxy") Unable to connect to broker at ip.spipe:usrdrtm041ccpr2.ssm.sdc.gts.ibm.com: status=0, "success", ncs/KDC1_STC_OK

      if (substr($logunit,0,12) eq "kraarreg.cpp") {
         if ($logentry eq "ConnectToProxy") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; # Successfully connected to CMS REMOTE_usrdrtm041ccpr2 using ip.spipe:#146.89.140.75[3660]
            if (substr($rest,1,22) eq "Successfully connected") {
               $rest =~ /to CMS (\S+) using (\S+)/;
               my $items = $1;
               my $iconn = $2;
               set_timeline($logtime,$l,$logtimehex,1,"Communications",substr($rest,1));
               $iconn =~ /\[(\d+)\]/;
               $iport = $1;
               if (defined $iport) {
                  my $m = $l . "a";
                  set_timeline($logtime,$m,$logtimehex,4,"Communications",$iport);  # record TEMS port
               }
               next;
            }
         }
         if ($logentry eq "PrimaryTEMSperiodicLookupThread") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;
            set_timeline($logtime,$l,$logtimehex,0,"Fallback",substr($rest,1));
            next;
         }
         if ($logentry eq "LookupAndRegisterWithProxy") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;
            set_timeline($logtime,$l,$logtimehex,0,"RegisterWithProxy",substr($rest,1));
            next;
         }
      }
      #(5A9E41FD.0053-698:kbbssge.c,52,"BSS1_GetEnv") CT_CMSLIST="IP.SPIPE:146.89.140.75;IP.PIPE:146.89.140.75;IP.SPIPE:146.89.140.76;IP.PIPE:146.89.140.76"
      if (substr($logunit,0,9) eq "kbbssge.c") {
         if ($logentry eq "BSS1_GetEnv") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; # CT_CMSLIST="IP.SPIPE:146.89.140.75;IP.PIPE:146.89.140.75;IP.SPIPE:146.89.140.76;IP.PIPE:146.89.140.76"
            $rest =~ / (\S+?)=(.*)/;
            my $ienv = $1;
            if (!defined $envx{$ienv}) {
               if (($opt_allenv == 1) or (defined $commenvx{$ienv})) {
                  $envx{$ienv} = 1;
                  set_timeline($logtime,$l,$logtimehex,0,"EnvironmentVariables",substr($rest,1));
               }
            }
            next;
         }
      }
      #(5AA2E3F5.0008-13E0:kraaulog.cpp,755,"IRA_OutputLogMsg") Connecting to CMS REMOTE_usrdrtm051ccpr2
      if (substr($logunit,0,12) eq "kraaulog.cpp") {
         if ($logentry eq "IRA_OutputLogMsg") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; #  Connecting to CMS REMOTE_usrdrtm051ccpr2
            set_timeline($logtime,$l,$logtimehex,0,"OPLOG",substr($rest,1));
            next;
         }
      }
      #(5AA2E3F5.0006-13E0:kdcc1wh.c,114,"conv__who_are_you") status=1c010008, "activity not in call", ncs/KDC1_STC_NOT_IN_CALL
      if (substr($logunit,0,9) eq "kdcc1wh.c") {
         if ($logentry eq "conv__who_are_you") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; #  status=1c010008, "activity not in call", ncs/KDC1_STC_NOT_IN_CALL
            set_timeline($logtime,$l,$logtimehex,0,"ANC",substr($rest,1));
            next;
         }
      }
      #(5AA2E3F1.0000-13E0:kdcc1sr.c,642,"rpc__sar") Endpoint unresponsive: "ip.spipe:#146.89.140.75:3660", 1C010001:1DE0000F, 210, 5(2), FFFF/1, D140831.1:1.1.1.13, tms_ctbs623fp3:d3086a
      #(5AA2E31C.0000-7E4:kdcc1sr.c,642,"rpc__sar") Remote call failure: 1C010001
      #(5AB93569.0000-14C8:kdcc1sr.c,670,"rpc__sar") Connection lost: "ip.spipe:#146.89.140.75:65100", 1C010001:1DE0004D, 30, 100(5), FFFF/40, D140831.1:1.1.1.13, tms_ctbs630fp7:d6305a

      if (substr($logunit,0,9) eq "kdcc1sr.c") {
         if ($logentry eq "rpc__sar") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; #  Endpoint unresponsive: "ip.spipe:#146.89.140.75:3660", 1C010001:1DE0000F, 210, 5(2), FFFF/1, D140831.1:1.1.1.13, tms_ctbs623fp3:d3086a
            if (substr($rest,1,19) eq "Remote call failure") { # need more work here
               my %rpcref = ();
               $rpcrunx{$logthread} = \%rpcref;
            } else {
               set_timeline($logtime,$l,$logtimehex,2,"RPC",substr($rest,1));
            }
            next;
         }
      }
      #(5AA2E31F.0000-7E4:kraarpcm.cpp,1024,"evaluateStatus") RPC call Sample for <2817540636,3532653436> failed, status = 1c010001
      if (substr($logunit,0,12) eq "kraarpcm.cpp") {
         if ($logentry eq "evaluateStatus") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; # RPC call Sample for <2817540636,3532653436> failed, status = 1c010001
            set_timeline($logtime,$l,$logtimehex,2,"Communications",substr($rest,1));
            next;
         }
      }
      #(5AA2E3F4.0000-13E0:kdcl0cl.c,142,"KDCL0_ClientLookup") status=1c020006, "location server unavailable", ncs/KDC1_STC_SERVER_UNAVAILABLE
      if (substr($logunit,0,9) eq "kdcl0cl.c") {
         if ($logentry eq "KDCL0_ClientLookup") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; # status=1c020006, "location server unavailable", ncs/KDC1_STC_SERVER_UNAVAILABLE
            set_timeline($logtime,$l,$logtimehex,2,"Communications",substr($rest,1));
            next;
         }
      }


      #  Tracing notes
      #  error
      #  (unit:kraafmgr,Entry="Start" all er)
      #  (unit:kraafira,Entry="DriveDataCollection" all er)
      #  (unit:kraafira,Entry="~ctira" all er)
      #  (unit:kraafira,Entry="InsertRow" all er)
      #  (unit:kdsflt1,Entry="FLT1_FilterRecord" all er)
      #  (unit:kdsflt1,Entry="FLT1_BeginSample" all er)
      #  (unit:kraadspt,Entry="sendDataToProxy" all er)
      #  (unit:kraatblm,Entry="resetExpireTime" all er)
      #  (unit:kglhc1c all er)
      #  (unit:kraaevst,Entry="createDispatchSitStat" flow er)
      #  (unit:kraaevxp,Entry="CreateSituationEvent" detail er)

      # Following entry is the best source of situation information, but not always present if situations are being stopped and started
      # (54931626.0693-1F:kraaevst.cpp,300,"createDispatchSitStat") *EV-INFO: Exception<0> Situation UNIX_LAA_Bad_su_to_root_Warning <294650831.307234630> KUL.ULLOGENT Type<4> Interval<0> rowSize<2864> rowCount<0> rowData<1113CBA34>
      if (substr($logunit,0,12) eq "kraaevst.cpp") {
         if ($logentry eq "createDispatchSitStat") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2; # *EV-INFO: Exception<0> Situation UNIX_LAA_Bad_su_to_root_Warning <294650831.307234630> KUL.ULLOGENT Type<4> Interval<0> rowSize<2864> rowCount<0> rowData<1113CBA34>
            next if substr($rest,1,19) ne "*EV-INFO: Exception";
            $rest =~ /^.*Situation (\S+) \S+ (\S+) Type<(\d)> Interval<(\d+)> rowSize<(\d+)> /;
            $isitname = $1;
            $DB::single=2 if $opt_tsit eq $isitname;
            $itable = $2;
            $isittype = $3;
            $irowsize = $5;
            my $ht = $hsitdata{$isitname};
            if (!defined $ht) {
               my %htref = (
                              sitname => $isitname,
                              table => $itable,
                              type => $isittype,
                              rowsize => $irowsize,
                           );
               $hsitdata{$isitname} = \%htref;
               $tabsize{$itable} = $irowsize if !defined $tabsize{$itable};
            }
         }
         next;
      }

      # If log segments are wrapping around, wait until past segment zero for more understanding
      next if $skipzero;

      #   Following is typical for a sampled situation or a real time data request
      #   (5421D2F0.0550-D:kraafmgr.cpp,816,"Start") Start complete IBM_test_boa <1355809413,1339032522> on *.KLZPROC, status = 0
      #   (5429E381.00C3-1:kraafmgr.cpp,816,"Start") Start complete  <1823474271,2838496211> on *.KLZPROC, status = 0
      if (substr($logunit,0,12) eq "kraafmgr.cpp") {
         if ($logentry eq "Start") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Start complete IBM_test_boa <1355809413,1339032522> on *.KLZPROC, status = 0
            next if substr($rest,1,14) ne "Start complete";
            $rest = substr($rest,16);
            if (substr($rest,0,1) eq " ") {
               $rest =~ / <(.*?)> on (\S+),/;
               $isitname = "*REALTIME";
               $iobjid = $1;
            } else {
               $rest =~ /(\S+) <(.*?)> on (\S+),/;
               $isitname = $1;
               $DB::single=2 if $opt_tsit eq $isitname;
               $iobjid = $2;
            }
            $ithread = $logthread;
            $sitseq += 1;                               # set new count
            my %sitref =(                               # anonymous hash for situation instance capture
                        thread => $logthread,           # Thread id associated with command capture
                        sitname => $isitname,           # Name of Situation
                        objid => $iobjid,               # stamp - hex time
                        start => $logtime,              # Decimal time start
                        state => 1,                     # state = 1 means looking for expired.
                        colcount => 0,                  # number of collection samples
                        colrows => 0,                   # number of rows collected
                        colfilt => 0,                   # number of rows after filter
                        coltime => 0,                   # seconds recorded for collection
                        colstart => 0,                  # seconds when collection recorded
                        sendrows => 0,                  # number of rows sent to TEMS
                        sendtime => 0,                  # seconds when rows sent to TEMS
                        sendct => 0,                    # number of times rows sent to TEMS
                        rowsize => 0,                   # size of rows
                        seq => $sitseq,                 # sequence of new sits
                        exptime => 0,                   # situation expiry time
                        table => "",                    # attribute table
                        time_expired => 0,              # seconds when evaluation starts
                        time_sample => 0,               # seconds when sample started
                        time_sample_exit => 0,          # seconds when sample finished
                        time_send => 0,                 # seconds when send to TEMS started
                        time_send_exit => 0,            # seconds when send to TEMS finished
                        time_complete => 0,             # seconds when evaluation process complete
                        time_next => 0,                 # seconds when evaluation next scheduled
                        delaysample => 0,               # total delay to sample
                        delaysend => 0,                 # total delay to send
                        delayeval => 0,                 # total delay to next evaluation
                        slots => {},                    # hold details when wanted
            );
            $sitrun{$iobjid} = \%sitref;
            if (defined $sit_details{$isitname}) {
               my $slot = getstamp($logtime);
               my $slot_ref = $sitref->{slots}{$slot};
               if (!defined $slot_ref) {
                  my %slotref = (
                                   instance => 0,
                                   sendrows => 0,                  # number of rows sent to TEMS
                                   sendtime => 0,                  # seconds recorded for rows sent to TEMS
                                   sendct => 0,                    # number of times rows sent to TEMS
                                   coltime => 0,
                                   delayeval => 0,
                                   delaysample => 0,
                                   delaysend => 0,
                                   colcount => 0,                  # number of collection samples
                                   colrows => 0,                   # number of rows collected
                                   colfilt => 0,                   # number of rows after filter
                                   coltime => 0,                   # seconds recorded for collection
                                   rowsize => 0,                   # size of rows
                                );
                  $sitref->{slots}{$slot} = \%slotref;
                  $slot_ref = \%slotref;
               }
               $slot_ref->{instance} += 1;
            }
         }
         next;
      }

      # and record situation name, attribute table, and request key
      # *note* there may be more then one request/table associated with a situation
      #        could be many of them. Also there may be more then one situation instance
      #        as situation stop and start. Situation with Action command have two instances.

      # Stopping a situation
      #   (54220145.001C-1:kraafmgr.cpp,841,"Stop") Stop received for IBM_test_boa_1 <1357906597,1339032502> on KLZ.KLZPROC, status = 0
      #   (54220145.001D-1:klz07agt.cpp,611,"TakeSampleDestructor") Situation IBM_test_boa_1 has been stopped. Removing from the map.
      #   (54220145.001F-1:kraafira.cpp,404,"~ctira") Deleting request @0x8094fe80 <1357906597,1339032502> KLZ.KLZPROC, IBM_test_boa_1
      #   (54220145.0020-1:kraafira.cpp,425,"~ctira") Stopping Enterprise situation IBM_test_boa_1 <1357906597,1339032502>, on KLZ.KLZPROC.
      # at this point situation instance is complete

      # watch for this sequence

      #   (5421D2F0.0F30-F:kraatblm.cpp,1040,"resetExpireTime") Situation IBM_test_boa <1362101196,1339032516> expired at 1411502832 and will next expire at 1411502862 : timeTaken = 0
      #  note data has the elapsed time of data sample process

      #   (5421D2F0.0F33-F:kraafira.cpp,890,"DriveDataCollection") KLZ.KLZPROC, <1370489807,1339032510> IBM_test_boa_4 expired.
      # after this point can see to show rows filtered away
      #    (5422F619.1D27-F:kdsflt1.c,1427,"FLT1_FilterRecord") Entry
      #    (5422F619.1D28-F:kdsflt1.c,1464,"FLT1_FilterRecord") Exit: 0x1
      # or following shows rows that were not filtered away
      #    (5422F619.19A4-F:kdsflt1.c,1427,"FLT1_FilterRecord") Entry
      #    (5422F619.19A5-F:kdsflt1.c,1464,"FLT1_FilterRecord") Exit: 0x0
      # and that way count of data rows provided and filtered

      # When seeing this row data collect is complete
      #   (5421D2F0.0FEE-F:kraafira.cpp,1023,"DriveDataCollection") Exit: 0x0

      # here is an example where no data is returned from data collection

      #   (5421D2F0.10BC-F:kraafira.cpp,880,"DriveDataCollection") Entry
      #   (5421D2F0.10BD-F:kraafira.cpp,890,"DriveDataCollection") KLZ.KLZPROC, <1357906681,1339032506> IBM_test_boa_1 expired.
      #   (5429E381.00DB-8:kraafira.cpp,890,"DriveDataCollection") KLZ.KLZPROC, <1823474271,2838496211>  expired.   *note* no situation name
      #   (54220145.001F-1:kraafira.cpp,404,"~ctira") Deleting request @0x8094fe80 <1357906597,1339032502> KLZ.KLZPROC, IBM_test_boa_1


      if (substr($logunit,0,12) eq "kraafira.cpp") {
         if ($logentry eq "DriveDataCollection") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # KLZ.KLZPROC, <1357906681,1339032506> IBM_test_boa_1 expired.
            if (substr($rest,-8,8) eq "expired.") {
               $rest =~ / (\S+), <(.*?)> (.+)$/;
               $itable = $1;
               $iobjid = $2;
               $isitname = $3;
               if (substr($isitname,1,8) eq "expired.") {
                  $isitname = "*REALTIME";
               } else {
                  $isitname =~ /(\S+) /;
                  $isitname = $1;
                  $DB::single=2 if $opt_tsit eq $isitname;
               }
               if ($sit_start == 0) {
                  $sit_start = $logtime;
                  $sit_end = $logtime;
               }
               if ($logtime < $sit_start) {
                  $sit_start = $logtime;
               }
               if ($logtime > $sit_end) {
                  $sit_end = $logtime;
               }
               $sitref = $sitrun{$iobjid};
               if (!defined $sitref) {
                  $sitseq += 1;                               # set new count
                  my %sitref = (                              # anonymous hash for situation instance capture
                              thread => $logthread,           # Thread id associated with command capture
                              sitname => $isitname,           # Name of Situation
                              objid => $iobjid,               # stamp - hex time
                              start => $logtime,              # Decimal time start
                              state => 1,                     # state = 1 means looking Drive Data Collection
                              colcount => 0,                  # number of collection samples
                              colrows => 0,                   # number of rows collected
                              colfilt => 0,                   # number of rows after filter
                              coltime => 0,                   # seconds recorded for collection
                              colstart => 0,                  # seconds when collection recorded
                              sendrows => 0,                  # number of rows sent to TEMS
                              sendtime => 0,                  # seconds when rows sent to TEMS
                              sendct => 0,                    # number of times rows sent to TEMS
                              rowsize => 0,                   # size of rows
                              seq => $sitseq,                 # sequence of new sits
                              exptime => 0,                   # situation expiry time
                              table => $itable,               # attribute table
                              time_expired => 0,              # seconds when evaluation starts
                              time_sample => 0,               # seconds when sample started
                              time_sample_exit => 0,          # seconds when sample finished
                              time_send => 0,                 # seconds when send to TEMS started
                              time_send_exit => 0,            # seconds when send to TEMS finished
                              time_complete => 0,             # seconds when evaluation process complete
                              time_next => 0,                 # seconds when evaluation next scheduled
                              delaysample => 0,               # total delay to sample
                              delaysend => 0,                 # total delay to send
                              delayeval => 0,                 # total delay to next evaluation
                              slots => {},                    # hold details when wanted
                  );
                  $sitrun{$iobjid} = \%sitref;
                  $sitref = \%sitref;
               }
               if (defined $sit_details{$isitname}) {
                  my $slot = getstamp($logtime);
                  my $slot_ref = $sitref->{slots}{$slot};
                  if (!defined $slot_ref) {
                     my %slotref = (
                                      instance => 0,
                                      sendrows => 0,                  # number of rows sent to TEMS
                                      sendct => 0,                    # number of times rows sent to TEMS
                                      coltime => 0,
                                      delayeval => 0,
                                      delaysample => 0,
                                      delaysend => 0,
                                      colcount => 0,                  # number of collection samples
                                      colrows => 0,                   # number of rows collected
                                      colfilt => 0,                   # number of rows after filter
                                      coltime => 0,                   # seconds recorded for collection
                                      rowsize => 0,                   # size of rows
                                   );
                     $sitref->{slots}{$slot} = \%slotref;
                     $slot_ref = \%slotref;
                  }
                  $slot_ref->{colcount} += 1;
               }
               $sitref->{state} = 2;
               $sitref->{colcount} += 1;
               $sitref->{exptime} = $logtime;
               $sitref->{table} = $itable;
               $sitref->{time_expired} = $logtime;
               $sitref->{time_sample} = 0;
               $sitref->{time_sample_exit} = 0;
               $sitref->{time_send} = 0;
               $sitref->{time_send_exit} = 0;
               my %capref = (type => 1,                      # sampled capture = 1
                             state => 0,                     # track between capture records
                             objid => $iobjid,               # object id
                             sitname => $isitname,           # situation name
                             filtered => 0,                  # number of rows filtered
                             sent => 0,                      # number of rows sent
                             table => "",                    # related table
                             time_send => 0,                 # time send to TEMS starts
                   );
               $thrun{$logthread} = \%capref;                # Associate capture record with thread number
            } elsif (substr($rest,1,5) eq "Exit:") {
               my $cap_ref = $thrun{$logthread};
               if (defined $cap_ref) {
                  if ($cap_ref->{type} == 1) {
                     $iobjid = $cap_ref->{objid};
                     $sitref = $sitrun{$iobjid};
                     if (defined $sitref) {
                        if ($sitref->{state} == 2) {         # end of DriveDataCollection
                           $sitref->{state} = 3;
                        }
                     }
                  }
               }
            }
            next;
         } elsif ($logentry eq "~ctira") {
            $oneline =~ /^\((\S+)\)(.+)$/;
                                              # seen when situation being stopped or after real time request finished
            $rest = $2;                       # Deleting request @0x8094fe80 <1357906597,1339032502> KLZ.KLZPROC, IBM_test_boa_1
            if (substr($rest,1,8) eq "Deleting") {
               $rest =~ /.*? <(.*?)> (\S+), (\S+)/;
               $iobjid = $1;
               $itable = $2;
               $isitname = $3;
               $sitref = $sitrun{$iobjid};
               if (defined $sitref) {
                  $histruni += 1;
                  my $histref = { %$sitref };      # reference to shallow copy
                  $histrun[$histruni] = $histref;  # save in history
                  delete $sitrun{$iobjid};         # forget run reference
               }
            }
         } elsif ($logentry eq "ctira") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Creating request @0x808db1b0 <1825571755,2836399068> KPX.KPXSCHED, NonPrimeShift
                                              # Creating request @0x8068ab30 <1823474271,2838496211> KLZ.KLZPROC,
            if (substr($rest,1,8) eq "Creating") {
               $rest =~ /.*? <(.*?)> (.+)$/;
               $iobjid = $1;
               $rest = $2;
               if (index($rest," ") > -1) {
                  $rest =~ /(\S+), (\S+)$/;
                  $itable = $1;
                  $isitname = $2;
                  $DB::single=2 if $opt_tsit eq $isitname;
               } else {
                  $rest =~ /(\S+),$/;
                  $itable = $1;
                  $isitname = "*REALTIME";
               }
               $sitref = $sitrun{$iobjid};
               if (!defined $sitref) {
                  $sitseq += 1;                               # set new count
                  my %sitref =(                               # anonymous hash for situation instance capture
                              thread => $logthread,           # Thread id associated with command capture
                              sitname => $isitname,           # Name of Situation
                              objid => $iobjid,               # stamp - hex time
                              start => $logtime,              # Decimal time start
                              state => 1,                     # state = 1 means looking Drive Data Collection
                              colcount => 0,                  # number of collection samples
                              colrows => 0,                   # number of rows collected
                              colfilt => 0,                   # number of rows after filter
                              coltime => 0,                   # seconds recorded for collection
                              colstart => 0,                  # seconds when collection recorded
                              sendrows => 0,                  # number of rows sent to TEMS
                              sendtime => 0,                  # seconds when rows sent to TEMS
                              sendct => 0,                    # number of times rows sent to TEMS
                              rowsize => 0,                   # size of rows
                              seq => $sitseq,                 # sequence of new sits
                              exptime => 0,                   # situation expiry time
                              table => $itable,               # attribute table
                              time_expired => 0,              # seconds when evaluation starts
                              time_sample => 0,               # seconds when sample started
                              time_sample_exit => 0,          # seconds when sample finished
                              time_send => 0,                 # seconds when send to TEMS started
                              time_send_exit => 0,            # seconds when send to TEMS finished
                              time_complete => 0,             # seconds when evaluation process complete
                              time_next => 0,                 # seconds when evaluation next scheduled
                              delaysample => 0,               # total delay to sample
                              delaysend => 0,                 # total delay to send
                              delayeval => 0,                 # total delay to next evaluation
                              slots => {},                    # hold details when wanted
                  );
                  $sitrun{$iobjid} = \%sitref;
               }
               if (defined $sit_details{$isitname}) {
                  my $slot = getstamp($logtime);
                  my $slot_ref = $sitref->{slots}{$slot};
                  if (!defined $slot_ref) {
                     my %slotref = (
                                      instance => 0,
                                      sendrows => 0,                  # number of rows sent to TEMS
                                      sendct => 0,                    # number of times rows sent to TEMS
                                      coltime => 0,
                                      delayeval => 0,
                                      delaysample => 0,
                                      delaysend => 0,
                                      colcount => 0,                  # number of collection samples
                                      colrows => 0,                   # number of rows collected
                                      colfilt => 0,                   # number of rows after filter
                                      coltime => 0,                   # seconds recorded for collection
                                      rowsize => 0,                   # size of rows
                                   );
                     $sitref->{slots}{$slot} = \%slotref;
                     $slot_ref = \%slotref;
                  }
                  $slot_ref->{instance} += 1;
               }
            }
         } elsif ($logentry eq "InsertRow") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # rowsize = 1540, newsize = 50, newbytes = 77000, _allocated = 0, _allocSize = 50
            if (substr($rest,1,7) eq "rowsize") {
               $rest =~ / rowsize = (\d+),/;
               $irowsize = $1;
               my $cap_ref = $thrun{$logthread};
               if (defined $cap_ref) {
                  if ($cap_ref->{type} == 1) {
                     $iobjid = $cap_ref->{objid};
                     $sitref = $sitrun{$iobjid};
                     if (defined $sitref) {
                        if ($sitref->{state} == 2) {
                           $sitref->{rowsize} = $irowsize;
                           $itable = $sitref->{table};
                           $tabsize{$itable} = $irowsize;
                           if (defined $sit_details{$sitref->{sitname}}) {
                              my $slot = getstamp($sitref->{exptime});
                              my $slot_ref = $sitref->{slots}{$slot};
                              $slot_ref->{rows} = $irowsize;
                           }
                        }
                     }
                  }
               }
            }
         }
      }
      # (5422F619.1AA2-F:kdsflt1.c,1464,"FLT1_FilterRecord") Exit: 0x1 or 0x0
      if (substr($logunit,0,9) eq "kdsflt1.c") {
         if ($logentry eq "FLT1_FilterRecord") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Exit: 0x1
            if (substr($rest,1,5) eq "Exit:") {
               # if there is already a capture record, probably a sampled situation
               my $cap_ref = $thrun{$logthread};
               if (defined $cap_ref) {
                  if ($cap_ref->{type} == 1) {
                     $iobjid = $cap_ref->{objid};
                     $sitref = $sitrun{$iobjid};
                     if (defined $sitref) {
                        if ($sitref->{state} == 2) {
                           $sitref->{colrows} += 1;
                           $sitref->{colfilt} += 1 if substr($rest,7,3) eq "0x0";
                        }
                        if (defined $sit_details{$sitref->{sitname}}) {
                           my $slot = getstamp($sitref->{exptime});
                           my $slot_ref = $sitref->{slots}{$slot};
                           $slot_ref->{colrows} += 1;
                           $slot_ref->{colfilt} += 1 if substr($rest,7,3) eq "0x0";
                        }
                     }
                  }
               # if no capture record, this is the first record of a pure situation record evaluation
               # the situation name arrives later but we need to record the filter success or failure now
               } else {
                  my %capref = (type => 4,                      # sampled capture = 1, pure capture = 4
                                state => 0,                     # track between capture records
                                objid => "",                    # object id
                                sitname => "",                  # situation name
                                table => "",                    # related table
                                filtered => 0,                  # number of rows filtered
                                sent => 0,                      # number of rows sent
                                time_send => 0,                 # time send to TEMS starts
                  );
                  $thrun{$logthread} = \%capref;
                  $cap_ref =  $thrun{$logthread};
                  $cap_ref->{filtered} += 1;
                  $cap_ref->{sent} += 1 if substr($rest,7,3) eq "0x0";
               }
            }
         } elsif ($logentry eq "FLT1_BeginSample") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Exit: 0x0 or Entry
            my $cap_ref = $thrun{$logthread};
            if (defined $cap_ref) {
               if ($cap_ref->{type} == 1) {
                  $iobjid = $cap_ref->{objid};
                  $sitref = $sitrun{$iobjid};
                  if (defined $sitref) {
                     if ($sitref->{state} == 2) {
                        if (substr($rest,1,5) eq "Entry") {
                           $sitref->{time_sample} = $logtime if $sitref->{time_sample} == 0;
                        } elsif (substr($rest,1,5) eq "Exit:") {
                           $sitref->{time_sample_exit} = $logtime;
                        }
                     }
                  }
               }
            }
            next;
         }
      }

      # capture pure situation sitname before sendDataProxy
      # (54931626.0DAE-11:kraaevxp.cpp,501,"CreateSituationEvent") *EV-INFO: Input event: obj=0x1111FA530, type=5, excep=0, numbRow=1, rowData=0x110ADF640, status=0, sitname="UNIX_LAA_Bad_su_to_root_Warning"
      if (substr($logunit,0,12) eq "kraaevxp.cpp") {
         if ($logentry eq "CreateSituationEvent") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;  #*EV-INFO: Input event: obj=0x1111FA530, type=5, excep=0, numbRow=1, rowData=0x110ADF640, status=0, sitname="UNIX_LAA_Bad_su_to_root_Warning"
            next if substr($rest,1,22) ne "*EV-INFO: Input event:";
            my $cap_ref = $thrun{$logthread};
            if (defined $cap_ref) {
               if ($cap_ref->{type} == 4) {
                  $rest =~ /sitname="(\S+)"/;
                  $isitname = $1;
                  $DB::single=2 if $opt_tsit eq $isitname;
                  my $ht_ref = $hsitdata{$isitname};
                  if (defined $ht_ref) {
                     if ($ht_ref->{type} == 4) {
                        $cap_ref->{sitname} = $isitname;
                        $cap_ref->{table} = $ht_ref->{table};
                     }
                  }
               }
            }
         }
      }


      # (5422F619.1C18-F:kraadspt.cpp,889,"sendDataToProxy") Sending 1 rows for IBM_Linux_Process KLZ.KLZPROC, <1374684111,2226127825>.
      if (substr($logunit,0,12) eq "kraadspt.cpp") {
         if ($logentry eq "sendDataToProxy") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Sending 1 rows for IBM_Linux_Process KLZ.KLZPROC, <1374684111,2226127825>.
            if (substr($rest,1,7) eq "Sending") {
               $rest =~ / Sending (\d+) rows for (.*?), <(.*?)>/;
               $srows = $1;
               $iobjid = $3;
               my $cap_ref = $thrun{$logthread};
               if (defined $cap_ref) {
                  $cap_ref->{time_send} = $logtime;
                  $cap_ref->{sent} = $srows if $cap_ref->{sent} == 0;
                  $isitname = $cap_ref->{sitname};
                  $sitref = $sitrun{$iobjid};
                  if (defined $sitref) {
                     if ($sitref->{sitname} eq "HEARTBEAT") {
                        $sitref->{colrows} += 1;
                        $sitref->{colfilt} += 1;
                     }
                     if ($sitref->{state} == 3) {
                        $sitref->{state} = 4;
                        $sitref->{sendrows} += $srows;
                        $sitref->{sendct} += 1;
                        $sitref->{time_send} = $logtime;
                     }
                     if (defined $sit_details{$sitref->{sitname}}) {
                        my $slot = getstamp($sitref->{exptime});
                        my $slot_ref = $sitref->{slots}{$slot};
                        $slot_ref->{sendrows} += $srows;
                        $slot_ref->{sendct} += 1;
                     }
                  }
               }
               next;

               # at exit, collect any pure situation capture and accumulate to pure sit hash
               # (54931626.0DBD-11:kraadspt.cpp,955,"sendDataToProxy") Exit
            }  elsif (substr($rest,1,4) eq "Exit") {
               my $cap_ref = $thrun{$logthread};
               if (defined $cap_ref) {
                  $isitname = $cap_ref->{sitname};
                  $DB::single=2 if $opt_tsit eq $isitname;
                  $iobjid = $cap_ref->{objid};
                  $sitref = $sitrun{$iobjid};
                  if ($cap_ref->{type} == 4) {            # pure situation
                     my $pure_ref = $sitpure{$isitname};
                     if (!defined $pure_ref) {
                        my %pureref = (
                                         table => $cap_ref->{table},
                                         rowsize => $cap_ref->{rowsize},
                                         filtered => 0,
                                         sent => 0,
                                         rowsize => 0,
                                      );
                        $sitpure{$isitname} = \%pureref;
                        $pure_ref = \%pureref;
                     }
                     $pure_ref->{filtered} += $cap_ref->{filtered};
                     $pure_ref->{filtered} += $cap_ref->{filtered};
                     if ($pure_start == 0) {
                        $pure_start = $logtime;
                        $pure_end = $logtime;
                     } elsif ($logtime < $pure_start) {
                        $pure_start = $logtime;
                     } elsif ($logtime > $pure_end) {
                        $pure_end = $logtime;
                     }
                  } else {                                # sampled situation
                     if ($sitref->{state} == 4) {
                        $sitref->{time_send_exit} = $logtime; # record sendDataToProxy end time
                        $flowkey = "T" . $cap_ref->{time_send};
                        $flow_ref = $flowtems{$flowkey};
                        if (!defined $flow_ref) {
                           my %flowref = (
                                            count => 0,
                                            instances =>[],
                                         );
                           $flow_ref = \%flowref;
                           $flowtems{$flowkey} = \%flowref;
                        }
                        $flow_ref->{count} += 1;
                        my %flowcase = (
                                          time_send => $cap_ref->{time_send},
                                          time_send_exit => $logtime,
                                          sendrows => $cap_ref->{sent},
                                          table => $sitref->{table},
                                          sitname => $sitref->{sitname},
                                       );
                        push (@{$flow_ref->{instances}},\%flowcase);
                        $sitref->{state} = 2;             # resume waiting for next expiry
                     }
                  }
               }
            }
         }
      }

      # (5422F619.1C1D-F:kraatblm.cpp,1040,"resetExpireTime") Situation IBM_Linux_Process <1374684111,2226127825> expired at 1411577369 and will next expire at 1411578269 : timeTaken = 0
      if (substr($logunit,0,12) eq "kraatblm.cpp") {
         if ($logentry eq "resetExpireTime") {
            $oneline =~ /^\((\S+)\)(.+)$/;
            $rest = $2;                       # Situation IBM_test_boa <1362101196,1339032516> expired at 1411502832 and will next expire at 1411502862 : timeTaken = 0
            next if substr($rest,1,9) ne "Situation";
            $rest =~ / Situation (\S+) <(.*?)> .*? will next expire at (\d+) .*? timeTaken = (\d+)/;
            $isitname = $1;
            $DB::single=2 if $opt_tsit eq $isitname;
            $iobjid = $2;
            $inext = $3;
            $itaken = $4;
            $ithread = $logthread;
            $sitref = $sitrun{$iobjid};
            if (defined $sitref) {
               $sitref->{state} = 2;                     # waiting for next DriveDataCollection
               $sitref->{coltime} += $itaken;            # time in data collection
               $DB::single=2 if $opt_tsit eq $isitname;
               $sitref->{sendtime} += $sitref->{time_send_exit} - $sitref->{time_send};       # time in sendDataToProxy
               $sitref->{time_next} = $sitref->{time_expired} if $sitref->{time_next} == 0;
               $sitref->{delayeval} += $sitref->{time_expired} - $sitref->{time_next};
               $sitref->{delaysample} += $sitref->{time_sample} - $sitref->{time_expired} if $sitref->{time_sample} > 0;
               $sitref->{delaysend} += $sitref->{time_send} - $sitref->{time_expired} if $sitref->{time_send} > 0;
               if (defined $sit_details{$sitref->{sitname}}) {
                  my $slot = getstamp($sitref->{exptime});
                  my $slot_ref = $sitref->{slots}{$slot};
                  $slot_ref->{coltime} += $itaken;
                  $slot_ref->{sendtime} += $sitref->{sendtime};
                  $slot_ref->{delayeval} += $sitref->{time_expired} - $sitref->{time_next};
                  $slot_ref->{delaysample} += $sitref->{time_sample} - $sitref->{time_expired} if $sitref->{time_sample} > 0;
                  $slot_ref->{delaysend} += $sitref->{time_send} - $sitref->{time_expired} if $sitref->{time_send} > 0;
               }
               $sitref->{time_next} = $inext;
               $sitref->{time_expired} = 0;
               $sitref->{time_sample} = 0;
               $sitref->{time_send} = 0;
               $sitref->{time_sendtime} = 0;
            }
            delete $thrun{$logthread} if defined $thrun{$logthread};
            next;
         }
      }

      # (53FE31BA.0043-61C:kglhc1c.c,563,"KGLHC1_Command") Entry
      # (53FE31BA.0044-61C:kglhc1c.c,592,"KGLHC1_Command") <0x190B3D18,0x8> Attribute type 0
      # +53FE31BA.0044     00000000   53595341 444D494E                      SYSADMIN
      # (53FE31BA.0045-61C:kglhc1c.c,601,"KGLHC1_Command") <0x190B4CFB,0x8A> Command String
      # +53FE31BA.0045     00000000   443A5C73 63726970  745C756E 69782031   D:\script\unix.1
      # +53FE31BA.0045     00000010   31343038 32373134  31353038 30303020   140827141508000.
      # +53FE31BA.0045     00000020   27554E49 585F4350  5527206C 74727364   'UNIX_CPU'.ltrsd
      # +53FE31BA.0045     00000030   3032303A 4B555820  2750726F 63657373   020:KUX.'Process
      # +53FE31BA.0045     00000040   20435055 20757469  6C697A61 74696F6E   .CPU.utilization
      # +53FE31BA.0045     00000050   20474520 38352069  73206372 69746963   .GE.85.is.critic
      # +53FE31BA.0045     00000060   616C2C20 20746865  20696E74 656E7369   al,..the.intensi
      # +53FE31BA.0045     00000070   7479206F 66206120  70726F63 65737320   ty.of.a.process.
      # +53FE31BA.0045     00000080   6973206F 66203938  2027                is.of.98.'
      # (53FE31BD.0000-61C:kglhc1c.c,862,"KGLHC1_Command") Exit: 0x0

      if (substr($logunit,0,9) eq "kglhc1c.c") {
         $oneline =~ /^\((\S+)\)(.+)$/;
         $rest = $2;
         if ($act_start == 0) {
            $act_start = $logtime;
            $act_end = $logtime;
         }
         if ($logtime < $act_start) {
            $act_start = $logtime;
         }
         if ($logtime > $act_end) {
            $act_end = $logtime;
         }
         if (substr($rest,1,6) eq "Entry") {             # starting a new command capture
             $act_id += 1;
             $runref = {                                # anonymous hash for command capture
                        thread => $logthread,           # Thread id associated with command capture
                        start => $logtime,              # Decimal time start
                        state => 1,                     # state = 1 means looking for command text
                        stamp => $logtimehex,           # stamp - hex time
                        cmd => "",                      # collected command text
                        cmd_tot => 0,                   # cmd expected length
                        id => $act_id,                  # action command id
             };
             $runx{$logthread} = $runref;
             $contkey = $logtimehex . "." . $logline;
             $contx{$contkey} = $runref;
             $act_current_cmds{$act_id} = $runref;            #
             my $current_act = keys %act_current_cmds;
             if ($current_act > $act_max) {
                $act_max = $current_act;
                @act_max_cmds = ();
                @act_max_cmds = values %act_current_cmds;
             }
         } else {
            $runref = $runx{$logthread};                     # is this a known command capture?
            if (defined $runref) {                           # ignore if process started before trace capture

               # (53FE31BD.0000-61C:kglhc1c.c,862,"KGLHC1_Command") Exit: 0x0
               if (substr($rest,1,4) eq "Exit") {             # Ending a command capture
                  my $cmd1 = $runref->{'cmd'};
                  my $testcmd = $cmd1 . " ";
                  my $testkey = substr($cmd1,0,index($cmd1," "));
                  my $ax = $actx{$testkey};
                  if (!defined $ax) {
                     $acti += 1;
                     $ax = $acti;
                     $act[$ax] = $testkey;
                     $actx{$testkey} = $ax;
                     $act_elapsed[$ax] = 0;
                     $act_ok[$ax] = 0;
                     $act_err[$ax] = 0;
                     $act_ct[$ax] = 0;
                     $act_act[$ax] = [];
                  }
                  $act_elapsed[$ax] += $logtime - $runref->{'start'};
                  $act_ct[$ax] += 1;
                  $act_ok[$ax] += 1 if substr($rest,7,3) eq "0x0";
                  $act_err[$ax] += 1 if substr($rest,7,3) ne "0x0";
                  push(@{$act_act[$ax]},$cmd1);
                  my $endid = $runref->{'id'};
                  delete $act_current_cmds{$endid};
               } else {
                  if (substr($rest,1,1) eq "<") {
                      # (53FE31BA.0044-61C:kglhc1c.c,592,"KGLHC1_Command") <0x190B3D18,0x8> Attribute type 0
                      # (53FE31BA.0045-61C:kglhc1c.c,601,"KGLHC1_Command") <0x190B4CFB,0x8A> Command String
                      $rest =~ /\<\S+\,(\S+)\> (.*)/;
                      my $vlen = $1;
                      $rest = $2;
                      $key = $logtimehex . "." . $logline;
                      if (substr($rest,0,9) eq "Attribute") {             # Attribute, unintesting
                         $runref->{'state'} = 2;

                      } else {
                         $runref->{'state'} = 3;
                         $runref->{'cmd'} = "";
                         $runref->{'cmd_tot'} = hex($vlen);
                      }
                       $contx{$key} = $runref;
                  }
               }
            }
         }
      }

   }
   set_timeline($logtime,$l,$logtimehex,3,"Log","End",);



   $sit_duration = $sit_end - $sit_start;
   $sit_duration = 1 if $sit_duration == 0;
   $tdur = $trcetime - $trcstime;
   $tdur = 1 if $tdur == 0;



   my $sittabi = -1;
   my @sittab  = ();
   my %sittabx = ();
   my @sittab_sit  = ();
   my @sittab_tab  = ();
   my @sittab_instance  = ();
   my @sittab_sendrows  = ();
   my @sittab_sendtime = ();
   my @sittab_colct  = ();
   my @sittab_colrows  = ();
   my @sittab_colbytes  = ();
   my @sittab_colfilt  = ();
   my @sittab_coltime  = ();
   my @sittab_objid = ();
   my @sittab_rowsize = ();
   my @sittab_delayeval = ();
   my @sittab_delaysample = ();
   my @sittab_delaysend = ();

   my $sittab_total_coltime = 0;
   my $sittab_total_colrows = 0;
   my $sittab_total_colsize = 0;
   my $sittab_total_colbytes = 0;

   for (my $i=0; $i<=$histruni; $i++) {
      $sitref = $histrun[$i];
      $sitrun{$sitref->{objid}} = $sitref;
   }

   foreach my $f (keys %sitrun) {
      $sitref = $sitrun{$f};
      $key = $sitref->{sitname} . "!" . $sitref->{table};
      $kx = $sittabx{$key};
      if (!defined $kx) {
         $sittabi += 1;
         $kx = $sittabi;
         $sittab[$kx] = $key;
         $sittabx{$key} = $kx;
         $sittab_sit[$kx] = $sitref->{sitname};
         $sittab_tab[$kx] = $sitref->{table};
         $sittab_instance[$kx] = 0;
         $sittab_sendrows[$kx] = 0;
         $sittab_sendtime[$kx] = 0;
         $sittab_colct[$kx] = 0;
         $sittab_colrows[$kx] = 0;
         $sittab_colbytes[$kx] = 0;
         $sittab_colfilt[$kx] = 0;
         $sittab_coltime[$kx] = 0;
         $sittab_rowsize[$kx] = 0;
         $sittab_objid[$kx] = "";
         $sittab_delayeval[$kx] = 0;
         $sittab_delaysample[$kx] = 0;
         $sittab_delaysend[$kx] = 0;
      }
      $sittab_instance[$kx] += 1;
      $sittab_sendrows[$kx] += $sitref->{sendrows};
      $sittab_sendtime[$kx] += $sitref->{sendtime};
      $sittab_colct[$kx] += $sitref->{colcount};
      $sittab_colrows[$kx] += $sitref->{colrows};
      $sittab_colfilt[$kx] += $sitref->{colfilt};
      $sittab_coltime[$kx] += $sitref->{coltime};
      $sittab_rowsize[$kx] = $sitref->{rowsize} if defined $sitref->{rowsize};
      $sittab_objid[$kx] .=  "\"" . $sitref->{objid} . "\"",;
      $sittab_delayeval[$kx] += $sitref->{delayeval};
      $sittab_delaysample[$kx] += $sitref->{delaysample};
      $sittab_delaysend[$kx] += $sitref->{delaysend};
   }

   # If no data was ever sent to the TEMS, the trace record will have no information
   # about row size. Row size is the number of bytes of data sent from the agent to
   # the TEMS and is an important clue for how much data is being processed.

   # First collect rowsize information when available.

   my %htabsum = ();                             # a hash of table name to row size

   for (my $i=0;$i<=$sittabi;$i++) {
      next if $sittab_rowsize[$i] == 0;
      next if $sittab_tab[$i] eq "";
      $htabsum{$sittab_tab[$i]} = $sittab_rowsize[$i];
   }

   # Review records with a zero row size and use if found from just calculated

   for (my $i=0;$i<=$sittabi;$i++) {
      next if $sittab_rowsize[$i] > 0;
      next if $sittab_tab[$i] eq "";
      my $looksize = $htabsum{$sittab_tab[$i]};
      next if !defined $looksize;
      $sittab_rowsize[$i] = $looksize;
   }

   # For any cases that are still missing, reference a built in table of rowsizes.

   for (my $i=0;$i<=$sittabi;$i++) {
      if ( $sittab_rowsize[$i] > 0) {
         $sittab_colbytes[$i] = $sittab_colrows[$i]*$sittab_rowsize[$i];
         next;
      }
      next if $sittab_tab[$i] eq "";
      my $looksize = $htabsize{$sittab_tab[$i]};
      next if !defined $looksize;
      $sittab_rowsize[$i] = $looksize;
      $sittab_colbytes[$i] = $sittab_colrows[$i]*$sittab_rowsize[$i];
      $htabsum{$sittab_tab[$i]} = $looksize;
   }

   # calculate totals

   for (my $i=0;$i<=$sittabi;$i++) {
      $sittab_total_coltime += $sittab_coltime[$i];
      $sittab_total_colrows += $sittab_colrows[$i];
      $sittab_total_colbytes += $sittab_colbytes[$i];
   }

   my $sittab_cum_coltime = 0;
   my $respc;
   my $ppc;

   my $pure_ct = 0;
   $pure_dur = $pure_end - $pure_start;
   $pure_dur = 1 if $pure_dur == 0;
   $cnt++;$oline[$cnt]="Agent Workload Audit Report by Pure Situation and Table sorted by Filtered Rows\n";
   $cnt++;$oline[$cnt]="\n";

   # report of netstat.info if it can be located

   my $netstatpath;
   my $netstatfn;
   my $gotnet = 0;
   $netstatpath = $opt_logpath;
   if ( -f $netstatpath . "netstat.info") {
      $gotnet = 1;
      $netstatpath = $opt_logpath;
   } elsif ( -f $netstatpath . "../netstat.info") {
      $gotnet = 1;
      $netstatpath = $opt_logpath . "../";
   } elsif ( -f $netstatpath . "../../netstat.info") {
      $gotnet = 1;
      $netstatpath = $opt_logpath . "../../";
   }
   $netstatpath = '"' . $netstatpath . '"';

   if ($gotnet == 1) {
      if ($gWin == 1) {
         $pwd = `cd`;
         chomp($pwd);
         $netstatpath = `cd $netstatpath & cd`;
      } else {
         $pwd = `pwd`;
         chomp($pwd);
         $netstatpath = `(cd $netstatpath && pwd)`;
      }

      chomp $netstatpath;

      $netstatfn = $netstatpath . "/netstat.info";
      $netstatfn =~ s/\\/\//g;    # switch to forward slashes, less confusing when programming both environments

      chomp($netstatfn);
      chdir $pwd;

      my $active_line = "";
      my $descr_line = "";
      my @nzero_line;
      my %nzero_ports = (
                           '1918' => 1,
                           '3660' => 1,
                           '63358' => 1,
                           '65100' => 1,
                        );

      my %inbound;
      my $inbound_ref;

      if (defined $netstatfn) {
         open NETS,"< $netstatfn" or warn " open netstat.info file $netstatfn -  $!";
         my @nts = <NETS>;
         close NETS;

         # sample netstat outputs

         # Active Internet connections (including servers)
         # PCB/ADDR         Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)
         # f1000e000ca7cbb8 tcp4       0      0  *.*                   *.*                   CLOSED
         # f1000e0000ac93b8 tcp4       0      0  *.*                   *.*                   CLOSED
         # f1000e00003303b8 tcp4       0      0  *.*                   *.*                   CLOSED
         # f1000e00005bcbb8 tcp        0      0  *.*                   *.*                   CLOSED
         # f1000e00005bdbb8 tcp4       0      0  *.*                   *.*                   CLOSED
         # f1000e00005b9bb8 tcp6       0      0  *.22                  *.*                   LISTEN
         # ...
         # Active UNIX domain sockets
         # Active Internet connections (servers and established)
         #
         # Active Internet connections (servers and established)
         # Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
         # tcp        0      0 0.0.0.0:1920                0.0.0.0:*                   LISTEN      18382/klzagent
         # tcp        0      0 0.0.0.0:34272               0.0.0.0:*                   LISTEN      18382/klzagent
         # tcp        0      0 0.0.0.0:28002               0.0.0.0:*                   LISTEN      5955/avagent.bin
         # ...
         # Active UNIX domain sockets (servers and established)

         my $l = 0;
         my $netstat_state = 0;                 # seaching for "Active Internet connections"
         my $recvq_pos = -1;
         my $sendq_pos = -1;
         foreach my $oneline (@nts) {
            $l++;
            chomp($oneline);
            if ($netstat_state == 0) {           # seaching for "Active Internet connections"
               next if substr($oneline,0,27) ne "Active Internet connections";
               $active_line = $oneline;
               $netstat_state = 1;
            } elsif ($netstat_state == 1) {           # next line is column descriptor line
               $recvq_pos = index($oneline,"Recv-Q");
               $sendq_pos = index($oneline,"Send-Q");
               $descr_line = $oneline;
               $netstat_state = 2;
            } elsif ($netstat_state == 2) {           # collect non-zero send/recv queues
               last if index($oneline,"Active UNIX domain sockets") != -1;
               $oneline =~ /(tcp\S*)\s*(\d+)\s*(\d+)\s*(\S+)\s*(\S+)/;
               my $proto = $1;
               if (defined $proto) {
                  my $recvq = $2;
                  my $sendq = $3;
                  my $localad = $4;
                  my $foreignad = $5;
                  my $localport = "";
                  my $foreignport = "";
                  my $localsystem = "";
                  my $foreignsystem = "";
                  $localad =~ /(\S+)[:\.](\S+)/;
                  $localsystem = $1 if defined $1;
                  $localport = $2 if defined $2;
                  $foreignad =~ /(\S+)[:\.](\S+)/;
                  $foreignsystem = $1 if defined $1;
                  $foreignport = $2 if defined $2;
                  if ((defined $nzero_ports{$localport}) or (defined $nzero_ports{$foreignport}) or ($opt_allports == 1)) {
                     if (defined $recvq) {
                        if (defined $sendq) {
                           if (($recvq > 0) or ($sendq > 0)) {
                              next if ($recvq == 0) and ($sendq == 0);
                              push @nzero_line,$oneline;
                              $total_sendq += 1;
                              $total_recvq += 1;
                              $max_sendq = $sendq if $sendq > $max_sendq;
                              $max_recvq = $recvq if $recvq > $max_recvq;
                           }
                        }
                     }
                  }
                  if (defined $nzero_ports{$localport}) {
                     $inbound_ref = $inbound{$localport};
                     if (!defined $inbound_ref) {
                        my %inboundref = (
                                            instances => {},
                                            count => 0,
                                         );
                        $inbound_ref = \%inboundref;
                        $inbound{$localport} = \%inboundref;
                     }
                     $inbound_ref->{count} += 1;
                     $inbound_ref->{instances}{$foreignsystem} += 1;
                  }
               }
            }
         }

      }
      if (($total_sendq + $total_recvq) > 0) {
         $rptkey = "AGENTREPORT009";$advrptx{$rptkey} = 1;         # record report key
         $cnt++;$oline[$cnt]="\n";
         $cnt++;$oline[$cnt]="$rptkey: NETSTAT Send-Q and Recv-Q Report\n";
         $cnt++;$oline[$cnt]="netstat.info.log\n";
         $cnt++;$oline[$cnt]="$active_line\n";
         $cnt++;$oline[$cnt]="$descr_line\n";
         foreach my $line (@nzero_line) {
            $cnt++;$oline[$cnt]="$line\n";
         }
         $advisori++;$advisor[$advisori] = "Advisory: TCP Queue Delays $total_sendq Send-Q [max $max_sendq] Recv-Q [max $max_recvq]";
      }
   }

   # Communication activity timeline
      $rptkey = "AGENTREPORT010";$advrptx{$rptkey} = 1;         # record report key
      my $nstate = 1;                                           # waiting for TEMS connection
                                                               # 2 waiting for errors
      my $tems_last = "";
      my $tems_ip = "";
      my $tems_port = "";
      my $tems_time = 0;
      my $temsfail = 0;
      my $temsfail_ct = 0;
      my $temsfail_sec = 0;
      my $commfail_ct = 0;
      my $commfail_sec = 0;
      $cnt++;$oline[$cnt]="\n";
      $cnt++;$oline[$cnt]="$rptkey: Timeline of TEMS connectivity\n";
      $cnt++;$oline[$cnt]="LocalTime,Hextime,Line,Advisory/Report,Notes,\n";
      foreach $f ( sort { $a cmp $b} keys %timelinex) {
         my $tl_ref = $timelinex{$f};
         if ($nstate == 1) {
            if ($tl_ref->{badcom} == 1) {   # connected to CMS
               $tl_ref->{notes} =~ /Successfully connected to CMS (\S+) using (\S+)/;
               $tems_last = $1;
               $tems_ip = $2;
               $tems_time = $tl_ref->{time};
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
               $outl .= $tems_last . ",";
               $outl .= $tems_ip . ",";
               if ($commfail_ct == 0) {
                  $outl .= "Connecting to TEMS,";
               } else {   # comm errors
                  my $tsecs = $tl_ref->{time} - $commfail_sec;
                  my $psecs = $tsecs%86400;
                  my $pdays = int($tsecs/86400);
                  $pdiff = $pdays . "/" . strftime("\%H:\%M:\%S",gmtime($psecs));
                  $outl .= "Connecting to TEMS after $commfail_ct errors recorded over $pdiff,";
               }
               $commfail_ct = 0;
               $commfail_sec = 0;
               $cnt++;$oline[$cnt]="$outl\n";
               $nstate = 2;
            } elsif ($tl_ref->{badcom} == 2) {
               my $temsfail = 0;
               if ($tems_port ne "") {
                  $temsfail = 1 if index($tl_ref->{notes},$tems_port) != -1;
               }
               if ($temsfail == 0) {
                  $tl_ref->{notes} =~ /\#.*?\:(\d+)\"/;
                  $iport = $1;
                  $porterrx{$iport} += 1 if defined $iport;
                  $commfail_ct += 1;
                  $commfail_sec = $tl_ref->{time} if $commfail_sec == 0;
               } else {
                  $temsfail_ct += 1;
                  $temsfail_sec = $tl_ref->{time} if $temsfail_sec == 0;
               }
            } elsif ($tl_ref->{badcom} == 3) { #end of log
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
               $tems_time = $tl_ref->{time};
               my $tsecs = $tl_ref->{time} - $commfail_sec;
               my $psecs = $tsecs%86400;
               my $pdays = int($tsecs/86400);
               $pdiff = $pdays . "/" . strftime("\%H:\%M:\%S",gmtime($psecs));
               $outl .= "Ended with no connection to TEMS after $commfail_ct errors recorded over $pdiff,";
               $cnt++;$oline[$cnt]="$outl\n";
            } elsif ($tl_ref->{badcom} == 4) { #TEMS port defined
               $tems_port = $tl_ref->{notes};
            } elsif ($tl_ref->{badcom} == -1) { # start of log
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",Log,Start";
               $cnt++;$oline[$cnt]="$outl\n";
            }

         } elsif ($nstate == 2) {
            if ($tl_ref->{badcom} == 4) { #TEMS port defined
               $tems_port = $tl_ref->{notes};
            } elsif ($tl_ref->{badcom} == 1) {   # connected to CMS - again!
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
               $outl .= $tems_last . ",";
               $outl .= $tems_ip . ",";
               $tdiff = $tl_ref->{time} - $tems_time;
               my $psecs = $tdiff%86400;
               my $pdays = int($tdiff/86400);
               $pdiff = $pdays . "/" . strftime("\%H:\%M:\%S",gmtime($psecs));
               $outl .= "reconnect to TEMS $tems_last without obvious comm failure after $pdiff,";
               $cnt++;$oline[$cnt]="$outl\n";
               $tl_ref->{notes} =~ /Successfully connected to CMS (\S+) using (\S+)/;
               $tems_last = $1;
               $tems_ip = $2;
               $tems_time = $tl_ref->{time};
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
               $outl .= $tems_last . ",";
               $outl .= $tems_ip . ",";
               $outl .= "Connecting to TEMS,";
               $cnt++;$oline[$cnt]="$outl\n";
            } elsif ($tl_ref->{badcom} == 2) { # communications failure
               if ($tems_port ne "") {
                  if (index($tl_ref->{notes},$tems_port) != -1) {  # communications failure on TEMS port
                     $tdiff = $tl_ref->{time} - $tems_time;
                     my $psecs = $tdiff%86400;
                     my $pdays = int($tdiff/86400);
                     $pdiff = $pdays . "/" . strftime("\%H:\%M:\%S",gmtime($psecs));
                     $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
                     $outl .= "Communications failure after $pdiff,";
                     $cnt++;$oline[$cnt]="$outl\n";
                     $temsfail_ct = 1;
                     $temsfail_sec = $tl_ref->{time};
                     $tems_port = "";
                     $nstate = 1;
                  } else {
                     $tl_ref->{notes} =~ /\#.*?\:(\d+)\"/;
                     $iport = $1;
                     $porterrx{$iport} += 1 if defined $iport;
                     $commfail_ct = 1;
                     $commfail_sec = $tl_ref->{time};
                  }
               }
            } elsif ($tl_ref->{badcom} == 3) { # end of log
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
               $outl .= $tems_last . ",";
               $outl .= $tems_ip . ",";
               $tdiff = $tl_ref->{time} - $tems_time;
               my $psecs = $tdiff%86400;
               my $pdays = int($tdiff/86400);
               $pdiff = $pdays . "/" . strftime("\%H:\%M:\%S",gmtime($psecs));
               $outl .= "Log ended with connection to TEMS $tems_last after $pdiff,";
               my $porterr_ct = scalar keys %porterrx;
               if ($porterr_ct > 0) {
                  $pporterr = "non-TEMS port errors:";
                  foreach my $p (keys %porterrx) {
                     $pporterr .= $p . "[" . $porterrx{$p} . "] ";
                  }
                 chop $pporterr;
                 $pporterr .= ",";
               }
               $outl .= $pporterr if defined $pporterr;
               $cnt++;$oline[$cnt]="$outl\n";
            } elsif ($tl_ref->{badcom} == -1) { # Start of log
               $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",Log,Start";
               $cnt++;$oline[$cnt]="$outl\n";
            }
         }
      }

      $rptkey = "AGENTREPORT011";$advrptx{$rptkey} = 1;         # record report key
      $cnt++;$oline[$cnt]="\n";
      $cnt++;$oline[$cnt]="$rptkey: Timeline of Communication events\n";
      $cnt++;$oline[$cnt]="LocalTime,Hextime,Line,Advisory/Report,Notes,\n";
      foreach $f ( sort { $a cmp $b} keys %timelinex) {
         my $tl_ref = $timelinex{$f};
         if ($tl_ref->{advisory} eq "EnvironmentVariables") {
            if (index($tl_ref->{notes},"KDE_TRANSPORT") != -1) {
               if (index($tl_ref->{notes},"idle:") != -1) {
                  $advisori++;$advisor[$advisori] = "Advisory: KDC_FAMILIES includes idle: setting - $tl_ref->{notes}";
               }
            }
         }
         $outl = sec2ltime($tl_ref->{time}+$local_diff) . ",";
         $outl .= $tl_ref->{hextime} . ",";
         $outl .= $tl_ref->{l} . ",";
         $outl .= $tl_ref->{advisory} . ",";
         $outl .= $tl_ref->{notes} . ",";
         $cnt++;$oline[$cnt]="$outl\n";

         my $mkey = sec2ltime($tl_ref->{time}+$local_diff) . "|" . $tl_ref->{l};
         my $ml_ref = $timelinexx{$mkey};
         if (!defined $ml_ref) {
            my %mlref = (   time => $tl_ref->{time},
                            hextime => $tl_ref->{hextime},
                            l => $tl_ref->{l},
                            advisory => $tl_ref->{advisory},
                            notes => $tl_ref->{notes},
                            logbase => $logbase,
                        );

            $ml_ref = \%mlref;
            $timelinexx{$mkey} = \%mlref;
         }
   }

   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="Situation,Table,Filtered_Rows,Filt_min,Sendrows,Send_min,Row_Size,Collect_Bytes,Collect_min\n";
   foreach my $f ( sort { $sitpure{$b}->{filtered} <=> $sitpure{$a}->{filtered} or
                          $a cmp $b
                        } keys %sitpure ) {
      next if $f eq "";
      $pure_ct += 1;
      $outl = $f . ",";
      $outl .= $sitpure{$f}->{table} . ",";
      $outl .= $sitpure{$f}->{filtered} . ",";
      my $persec = int(($sitpure{$f}->{filtered}*60)/$pure_dur);
      $outl .= $persec . ",";
      $outl .= $sitpure{$f}->{sent} . ",";
      $persec = int(($sitpure{$f}->{sent}*60)/$pure_dur);
      $outl .= $persec . ",";
      my $itable = $sitpure{$f}->{table};
      my $irowsize = $htabsize{$itable};
      $outl .= $irowsize . ",";
      my $cbytes = $sitpure{$f}->{filtered} * $irowsize;
      $outl .= $cbytes . ",";
      $persec = int(($cbytes*60)/$pure_dur);
      $outl .= $persec . ",";
      $cnt++;$oline[$cnt]="$outl\n";
   }
   if ($pure_ct > 0 ) {
      $cnt++;$oline[$cnt]="*Total," . $pure_dur . ",\n";
   }

   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="Agent Workload Audit Report by Sampled Situation and Table sorted by Collection Time\n";
   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="Situation,Table,Time_Taken,TT%,TT%cum,Instance,Collections,Sendrows,Sendtime,Collect_Rows,Collect_Filter,Collect_Bytes,Row_Size,Delay_Eval,DelaySample,Delay_Send,Taken_Per_Collection\n";
   foreach my $f ( sort { $sittab_coltime[$sittabx{$b}] <=> $sittab_coltime[$sittabx{$a}] or
                          $a cmp $b
                        } keys %sittabx ) {
      my $i = $sittabx{$f};
   #  next if $sittab_sit[$i] eq "dummysit";
      $outl = $sittab_sit[$i] . ",";
      $outl .= $sittab_tab[$i] . ",";
      $outl .= $sittab_coltime[$i] . ",";
      $sittab_cum_coltime += $sittab_coltime[$i];
      $res_pc = 0;
      $res_pc = int(($sittab_coltime[$i]*100)/$sittab_total_coltime) if $sittab_total_coltime > 0;
      $ppc = sprintf '%.0f%%', $res_pc;
      $outl .= $ppc . ",";
      $res_pc = 0;
      $res_pc = int(($sittab_cum_coltime*100)/$sittab_total_coltime) if $sittab_total_coltime > 0;
      $ppc = sprintf '%.0f%%', $res_pc;
      $outl .= $ppc . ",";
      $outl .= $sittab_instance[$i] . ",";
      $outl .= $sittab_colct[$i] . ",";
      $outl .= $sittab_sendrows[$i] . ",";
      $outl .= $sittab_sendtime[$i] . ",";
      $outl .= $sittab_colrows[$i] . ",";
      $outl .= $sittab_colfilt[$i] . ",";
      $outl .= $sittab_colbytes[$i] . ",";
      $outl .= $sittab_rowsize[$i] . ",";
      $outl .= $sittab_delayeval[$i] . ",";
      $outl .= $sittab_delaysample[$i] . ",";
      $outl .= $sittab_delaysend[$i] . ",";
      $res_pc = int(($sittab_coltime[$i])/$sittab_colct[$i]) if $sittab_colct[$i] > 0;
      $ppc = sprintf '%.0f', $res_pc;
      $outl .= $ppc . ",";
      $outl .= $sittab_objid[$i] . "," if $opt_objid == 1;
      $cnt++;$oline[$cnt]="$outl\n";
   }
   if ($sittab_total_coltime >= $sit_duration) {
      $advisori++;$advisor[$advisori] = "Advisory: Capture duration[$sit_duration] less then collection time[$sittab_total_coltime]";
   }
   $outl = "Duration," . $sit_duration . "," . $sittab_total_coltime . ",,,,,,,," . $sittab_total_colbytes . ",,,";
   $cnt++;$oline[$cnt]="$outl\n";


   my $sittab_cum_colbytes = 0;

   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="Agent Workload Audit Report by Situation and Table Sorted by Collected Bytes\n";
   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="Situation,Table,Time_Taken,Instance,Collections,Sendrows,SendTime,Collect_Rows,Collect_Filter,Collect_Bytes,CB%,CB%cum,Row_Size,Delay_Eval,DelaySample,Delay_Send\n";
   foreach my $f ( sort { $sittab_colbytes[$sittabx{$b}] <=> $sittab_colbytes[$sittabx{$a}] or
                          $a cmp $b
                        } keys %sittabx ) {
      my $i = $sittabx{$f};
   #  next if $sittab_sit[$i] eq "dummysit";
      $outl = $sittab_sit[$i] . ",";
      $outl .= $sittab_tab[$i] . ",";
      $outl .= $sittab_coltime[$i] . ",";
      $outl .= $sittab_instance[$i] . ",";
      $outl .= $sittab_colct[$i] . ",";
      $outl .= $sittab_sendrows[$i] . ",";
      $outl .= $sittab_sendtime[$i] . ",";
      $outl .= $sittab_colrows[$i] . ",";
      $outl .= $sittab_colfilt[$i] . ",";
      $outl .= $sittab_colbytes[$i] . ",";
      $res_pc = 0;
      $res_pc = int($sittab_colbytes[$i]*100)/$sittab_total_colbytes  if $sittab_total_colbytes > 0;
      $ppc = sprintf '%.0f%%', $res_pc;
      $outl .= $ppc . ",";
      $sittab_cum_colbytes += $sittab_colbytes[$i];
      $res_pc = 0;
      $res_pc = int($sittab_cum_colbytes*100)/$sittab_total_colbytes  if $sittab_total_colbytes > 0;
      $ppc = sprintf '%.0f', $res_pc;
      $outl .= $ppc . "%,";
      $outl .= $sittab_rowsize[$i] . ",";
      $outl .= $sittab_delayeval[$i] . ",";
      $outl .= $sittab_delaysample[$i] . ",";
      $outl .= $sittab_delaysend[$i] . ",";
      $outl .= $sittab_objid[$i] . "," if $opt_objid == 1;
      $cnt++;$oline[$cnt]="$outl\n";
   }
   $outl = "Duration," . $sit_duration . "," . $sittab_total_coltime . ",,,,,," . $sittab_total_colbytes . ",,,";
   $cnt++;$oline[$cnt]="$outl\n";

   foreach my $f (keys %sitrun) {
      $sitref = $sitrun{$f};
      next if !defined $sit_details{$sitref->{sitname}};
      $cnt++;$oline[$cnt]="\n";
      $cnt++;$oline[$cnt]="Agent Workload Audit Detail Report for Situation $sitref->{sitname} Table $sitref->{table} ObjectId $f\n";
      my $prowsize = $htabsum{$sitref->{table}};
      $prowsize = 0 if !defined $prowsize;
      $cnt++;$oline[$cnt]="Slot_Time,Time_Taken,Collections,Send_count,Sendrows,SendTime,Collect_Rows,Collect_Filter,Collect_Bytes,Row_Size,Delay_Eval,DelaySample,Delay_Send\n";
      foreach my $s ( sort { $a <=> $b} keys %{$sitref->{slots}}) {
         my $slot_ref = $sitref->{slots}{$s};
         my $outl = $s . ",";
         $outl .= $slot_ref->{coltime} . ",";
         $outl .= $slot_ref->{colcount} . ",";
         $outl .= $slot_ref->{sendct} . ",";
         $outl .= $slot_ref->{sendrows} . ",";
         $outl .= $slot_ref->{sendtime} . ",";
         $outl .= $slot_ref->{colrows} . ",";
         $outl .= $slot_ref->{colfilt} . ",";
         my $cb = $slot_ref->{colrows} * $prowsize;
         $outl .= $cb . ",";
         $outl .= $prowsize . ",";
         $outl .= $slot_ref->{delayeval} . ",";
         $outl .= $slot_ref->{delaysample} . ",";
         $outl .= $slot_ref->{delaysend} . ",";
         $cnt++;$oline[$cnt]="$outl\n";
      }
   }

   #flow report process
   foreach my $f (keys %flowtems) {
      $flow_ref = $flowtems{$f};
      my $fcount = $flow_ref->{count};
      for (my $i=0;$i<$flow_ref->{count};$i++){
         my $fcase_ref = $flow_ref->{instances}[$i];
         my $itime_send = $fcase_ref->{time_send};
         my $itime_send_exit = $fcase_ref->{time_send_exit};
         my $isendrows = $fcase_ref->{sendrows};
         my $itable = $fcase_ref->{table};
         my $isitname = $fcase_ref->{sitname};
         my $irowsize = $htabsize{$itable};
         $irowsize = 0 if !defined $irowsize;
         my $ibytes = $isendrows*$irowsize;
         my $ibyte_rate = int($ibytes/($itime_send_exit-$itime_send+1));
         for (my $j=$itime_send;$j<=$itime_send_exit;$j++) {
             my $rate_ref = $flowrate{$j};
             if (!defined $rate_ref) {
                my %rateref = (
                                 bytes => 0,
                                 count => 0,
                                 sitnames => {},
                                 tables => {},
                              );
                $rate_ref = \%rateref;
                $flowrate{$j} = \%rateref;
             }
             $rate_ref->{count} += 1;
             $rate_ref->{bytes} += $ibyte_rate;
             $rate_ref->{sitnames}{$isitname} += $ibyte_rate;
             $rate_ref->{tables}{$itable} += $ibyte_rate;
         }
      }
   }

   $cnt++;$oline[$cnt] = "\n";
   $cnt++;$oline[$cnt] = "Agent to TEMS flow report\n";
   $cnt++;$oline[$cnt] = "Time,Bytes,Rate,\n";
   foreach my $f ( sort { $a <=> $b} keys %flowrate) {
      my $rate_ref = $flowrate{$f};
      $outl = getstamp($f) . ",";
      $outl .= $rate_ref->{bytes} . ",";
      $outl .= $rate_ref->{count} . ",";
      my $psits = "";
      foreach my $g (keys %{$rate_ref->{sitnames}}) {
         $psits .= $g . "=" . $rate_ref->{sitnames}{$g} . ":";
      }
      $outl .= $psits . ",";
      $cnt++;$oline[$cnt]="$outl\n";
   }


   #print "\n";
   #print "Agent Workload Audit with Object ID\n";
   #print "Situation,Table,Instance,sendrows,SendTime,collections,collect_rows,collect_filter,collect_time,\n";
   #for (my $i=0;$i<=$sittabi;$i++) {
   #   my $oline = $sittab_objid[$i] . ",";
   #   $oline .= $sittab_sit[$i] . ",";
   #   $oline .= $sittab_tab[$i] . ",";
   #   $oline .= $sittab_instance[$i] . ",";
   #   $oline .= $sittab_sendrows[$i] . ",";
   #   $oline .= $sittab_sendtime[$i] . ",";
   #   $oline .= $sittab_colct[$i] . ",";
   #   $oline .= $sittab_colrows[$i] . ",";
   #   $oline .= $sittab_colfilt[$i] . ",";
   #   $oline .= $sittab_coltime[$i] . ",";
   #   print "$oline\n";
   #}

   my $act_ct_total = 0;
   my $act_ct_error = 0;
   my $act_elapsed_total = 0;
   my $act_duration;

   if ($acti != -1) {
      $act_duration = $act_end - $act_start;
      $cnt++;$oline[$cnt]="\n";
      $cnt++;$oline[$cnt]="Reflex Command Summary Report\n";
      $cnt++;$oline[$cnt]="Count,Error,Elapsed,Cmd\n";
      foreach $f ( sort { $act_ct[$actx{$b}] <=> $act_ct[$actx{$a}] ||
                          $act_act[$actx{$b}] cmp $act_act[$actx{$a}] } keys %actx ) {

         $i = $actx{$f};
         $outl = $act_ct[$i] . ",";
         $outl .= $act_err[$i] . ",";
         $outl .= $act_elapsed[$i] . ",";
         my @cmdarray = @{$act_act[$i]};
         my $pcommand = $cmdarray[0];
         $pcommand =~ s/\x09/\\t/g;
         $pcommand =~ s/\x0A/\\n/g;
         $pcommand =~ s/\x0D/\\r/g;
         $pcommand =~ s/\"/\"\"/g;
         $outl .= "\"" . $pcommand . "\"";
         $cnt++;$oline[$cnt]=$outl . "\n";
         $act_ct_total += $act_ct[$i];
         $act_ct_error += $act_err[$i];
         $act_elapsed_total += $act_elapsed[$i];

         if ($opt_cmdall == 1) {
            if ($#cmdarray > 0) {
               for (my $c=1;$c<=$#cmdarray;$c++) {
                  $outl = ",,,";
                  $pcommand = $cmdarray[$c];
                  $pcommand =~ s/\x09/\\t/g;
                  $pcommand =~ s/\x0A/\\n/g;
                  $pcommand =~ s/\x0D/\\r/g;
                  $pcommand =~ s/\x00/\\0/g;
                  $pcommand =~ s/\"/\"\"/g;
                  $pcommand =~ s/\'/\'\'/g;
                  $outl .= "\"" . $pcommand . "\",";
                  $cnt++;$oline[$cnt]=$outl . "\n";
               }
            }
         }
      }
      $outl = "duration" . " " . $act_duration . ",";
      $outl .= $act_elapsed_total . ",";
      $outl .= $act_ct_total . ",";
      $outl .= $act_ct_error . ",";
      $cnt++;$oline[$cnt]=$outl . "\n";
      if ($#act_max_cmds > 0) {
         $cnt++;$oline[$cnt]="\n";
         $outl = "Maximum action command overlay - $act_max";
         $cnt++;$oline[$cnt]=$outl . "\n";
         $outl = "Seq,Command";
         $cnt++;$oline[$cnt]=$outl . "\n";
         for (my $i = 0; $i <=$#act_max_cmds; $i++) {
            $runref = $act_max_cmds[$i];
            $outl = "$i,$runref->{cmd},";
            $cnt++;$oline[$cnt]=$outl . "\n";
         }
      }
   }
   if ($opt_pc ne "") {
      $opt_o = "agentaud_" . $opt_pc . ".csv" if $opt_o eq "agentaud.csv";
   }
   my $ofn = $opt_o;
   $ofn = $logbase . "_" . $opt_o if $opt_allinv == 1;

   open OH, ">$ofn" or die "can't open $ofn: $!";

   if ($opt_nohdr == 0) {
      for (my $i=0;$i<=$hdri;$i++) {
         $outl = $hdr[$i] . "\n";
         print OH $outl;
      }
      print OH "\n";
   }
   if ($advisori == -1) {
      print OH "No Expert Advisory messages\n";
   } else {
      for (my $i=0;$i<=$advisori;$i++){
         print OH "$advisor[$i]\n";
      }
   }
   print OH "\n";

   for (my $i=0;$i<=$cnt;$i++) {
      print OH $oline[$i];
   }

   close OH;
   close(ZOP) if $opt_zop ne "";
}


sub open_kib {
   # get list of files
   $logpat = $logbase . '-.*\.log' if defined $logbase;

   if (defined $logpat) {
      opendir(DIR,$opt_logpath) || die("cannot opendir $opt_logpath: $!\n");
      @dlogfiles = grep {/$logpat/} readdir(DIR);
      closedir(DIR);
      die "no log files found with given specifcation\n" if $#dlogfiles == -1;

      my $dlog;          # fully qualified name of diagnostic log
      my $oneline;       # local variable
      my $tlimit = 100;  # search this many times for a timestamp at begining of a log
      my $t;
      my $tgot;          # track if timestamp found
      my $itime;

      foreach $f (@dlogfiles) {
         $f =~ /^.*-(\d+)\.log/;
         $segmax = $1 if $segmax == 0;
         $segmax = $1 if $segmax < $1;
         $dlog = $opt_logpath . $f;
         open($dh, "< $dlog") || die("Could not open log $dlog\n");
         for ($t=0;$t<$tlimit;$t++) {
            $oneline = <$dh>;                      # read one line
            next if $oneline !~ /^.(.*?)\./;       # see if distributed timestamp in position 1 ending with a period
            $oneline =~ /^.(.*?)\./;               # extract value
            $itime = $1;
            next if length($itime) != 8;           # should be 8 characters
            next if $itime !~ /^[0-9A-F]*/;            # should be upper cased hex digits
            $tgot = 1;                             # flag gotten and quit
            last;
         }
         close($dh);
         if ($tgot == 0) {
            print STDERR "the log $dlog ignored, did not have a timestamp in the first $tlimit lines.\n";
            next;
         }
         $todo{$dlog} = hex($itime);               # Add to array of logs
      }
      $segmax -= 1;

      foreach $f ( sort { $todo{$a} <=> $todo{$b} } keys %todo ) {
         $segi += 1;
         $seg[$segi] = $f;
         $seg_time[$segi] = $todo{$f};
      }
   } else {
         $segi += 1;
         $seg[$segi] = $logfn;
         $segmax = 0;
   }
}
sub close_kib {
   close(KIB);
   $segp = -1;
}

sub read_kib {
   if ($segp == -1) {
      $segp = 0;
      if ($segmax > 0) {
         my $seg_diff_time = $seg_time[1] - $seg_time[0];
         if ($seg_diff_time > 3600) {
            $skipzero = 1;
         }
      }
      $segcurr = $seg[$segp];
      open(KIB, "<$segcurr") || die("Could not open log segment $segp $segcurr\n");
      print STDERR "working on $segp $segcurr\n" if $opt_v == 1;
      $hdri++;$hdr[$hdri] = '"' . "working on $segp $segcurr" . '"';
      $segline = 0;
   }
   $segline ++;
   $inline = <KIB>;
   return if defined $inline;
   close(KIB);
   $segp += 1;
   $skipzero = 0;
   return if $segp > $segi;
   $segcurr = $seg[$segp];
   open(KIB, "<$segcurr") || die("Could not open log segment $segp $segcurr\n");
   print STDERR "working on $segp $segcurr\n" if $opt_v == 1;
   $hdri++;$hdr[$hdri] = '"' . "working on $segp $segcurr" . '"';
   $segline = 1;
   $inline = <KIB>;
}

sub gettime
{
   my $sec;
   my $min;
   my $hour;
   my $mday;
   my $mon;
   my $year;
   my $wday;
   my $yday;
   my $isdst;
   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
   return sprintf "%4d-%02d-%02d %02d:%02d:%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec;
}

my %stampx;

sub getstamp {
   my $epoch = shift;
   my $hist_sec;
   my $hist_min;
   my $hist_hour;
   my $hist_day;
   my $hist_month;
   my $hist_year;
   my $stampr = $stampx{$epoch};
   if (!defined $stampr) {
      $hist_sec = (localtime($epoch))[0];
      $hist_sec = '00' . $hist_sec;
      $hist_min = (localtime($epoch))[1];
      $hist_min = '00' . $hist_min;
      $hist_hour = '00' . (localtime($epoch))[2];
      $hist_day  = '00' . (localtime($epoch))[3];
      $hist_month = (localtime($epoch))[4] + 1;
      $hist_month = '00' . $hist_month;
      $hist_year =  (localtime($epoch))[5] + 1900;
      $stampr = substr($hist_year,-2,2) . substr($hist_month,-2,2) . substr($hist_day,-2,2) .  substr($hist_hour,-2,2) .  substr($hist_min,-2,2) . substr($hist_sec,-2,2);
      $stampx{$epoch} = $stampr;
   }
   return $stampr;
}

sub sec2ltime
{
   my ($itime) = @_;

   my $sec;
   my $min;
   my $hour;
   my $mday;
   my $mon;
   my $year;
   my $wday;
   my $yday;
   my $isdst;
   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime($itime);
   return sprintf "%4d%02d%02d%02d%02d%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec;
}

sub set_timeline {
   my ($ilogtime,$il,$ilogtimehex,$ibadcom,$iadvisory,$inotes) = @_;
   $tlkey = $ilogtime . "|" . $il;
   $tl_ref = $timelinex{$tlkey};
   if (!defined $tl_ref) {
      my %tlref = (
                     time => $ilogtime,
                     l => $il,
                     hextime => $ilogtimehex,
                     advisory => $iadvisory,
                     notes => $inotes,
                     badcom => $ibadcom,
                  );
      $timelinex{$tlkey} = \%tlref;
   }
}



#------------------------------------------------------------------------------
sub GiveHelp
{
  $0 =~ s|(.*)/([^/]*)|$2|;
  print <<"EndOFHelp";

  $0 v$gVersion

  This script raeds a TEMS diagnostic log and writes a report of certain
  log records which record the result rows.

  Default values:
    none

  Run as follows:
    $0  <options> log_file

  Options
    -h              display help information
    -z              z/OS RKLVLOG log
    -b              Show HEARTBEATs in Managed System section
    -v              Produce limited progress messages in STDERR
    -inplace        [default and not used - see work parameter]
    -logpath        Directory path to TEMS logs - default current directory
    -work           Copy files to work directory before analyzing.
    -workpath       Directory path to work directory, default is the system
                    Environment variable Windows - TEMP, Linux/Unix tmp

  Examples:
    $0  logfile > results.csv

EndOFHelp
exit;
}
#------------------------------------------------------------------------------
# 0.50000 - new script based on temsaud.pl version 1.25000
# 0.60000 - extend logic and remove temsaud specific logic
# 0.70000 - clean up tests add -nohdr option for regression testing
#         - add -objid option, add duration tests
# 0.75000 - if available get situation list and validate running situations
# 0.76000 - Corrections for z/OS mode
#           Improve collecting rowsize
# 0.80000 - Report data on pure situations
# 0.81000 - Handle ITM 622 level traces
# 0.82000 - Add two rare KPX tables and KNT.NTMNTPT
#         - Correct pure event situation calculation
# 0.83000 - Add situation detail report over time
# 0.84000 - Report on sendDataToProxy time
#         - report on Flow to TEMS averaged by second
# 0.85000 - Correct z/OS diagnostic log logic
# 0.86000 - Add tracking of communication related issues
# 0.87000 - track non-TEMS communication errors separately.
#         - create merge.csv combined summary timeline if -allinv used
#         - handle alternate .inv name
