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

$gVersion = 0.88000;
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


# CPAN packages used
use Data::Dumper;               # debug
#use warnings::unused; # debug used to check for unused variables

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
my $opt_logpat;
my $opt_logpath;
my $full_logfn;
my $opt_v;
my $opt_vv;
my $workdel = "";
my $opt_cmdall;                                  # show all commands

my %stampx;
my %sendx;
my %sitevalx;
my %sitrowx;

#$sitevalx{"HEARTBEAT"} = 600;


sub gettime;                             # get time
sub getstamp;                            # convert epoch into slot stamp


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
my $cnt = -1;
my @oline = ();

my $sitseq = -1;                             # unique sit identifier


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


my %epoch = ();             # convert year/day of year to Unix epoch seconds
my $yyddd;
my $yy;
my $ddd;
my $days;
my $saveline;
my $oplogid;

my $lagline;
my $lagtime;
my $laglocus;

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

my $hdri = -1;                               # some header lines for report
my @hdr = ();                                #

$hdri++;$hdr[$hdri] = "TEMA Workload Advisory report v$gVersion";
my $audit_start_time = gettime();       # formated current time for report
$hdri++;$hdr[$hdri] = "Start: $audit_start_time";

#  following are the nominal values. These are used to generate an advisories section
#  that can guide usage of the Workload report. These can be overridden by the agentaud.ini file.

my $opt_nohdr;                               # when 1 no headers printed
my $opt_objid;                               # when 1 print object id
my $opt_o;                                   # when defined filename of report file
my $opt_tsit;                                # when defined debug testing sit
my $opt_slot;                                # when defined specify history slots, default 60 minutes
my $opt_txt;                    # input from .txt files
my $opt_txt_tsitdesc;           # TSITDESC txt file
my $opt_txt_tname;              # TNAME txt file
my $opt_lst;                    # input from .lst files
my $opt_lst_tsitdesc;           # TSITDESC lst file
my $opt_lst_tsitdesc1;          # TSITDESC_1 lst file
my $opt_lst_tname;              # TNAME lst file

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
   } elsif ($ARGV[0] eq "-o") {
      shift(@ARGV);
      if (defined $ARGV[0]) {
         if (substr($ARGV[0],0,1) ne "-") {
            $opt_o = shift(@ARGV);
         }
      }
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
   } elsif ($ARGV[0] eq "-txt") {
      $opt_txt = 1;
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-lst") {
      $opt_lst = 1;
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
if (!defined $opt_cmdall) {$opt_cmdall = 0;}
if (!defined $opt_nohdr) {$opt_nohdr = 0;}
if (!defined $opt_objid) {$opt_objid = 0;}
if (!defined $opt_tsit) {$opt_tsit = "";}
if (!defined $opt_o) {$opt_o = "agentaud.csv";}
if (!defined $opt_slot) {$opt_slot = 60;}
if (!defined $opt_v) {$opt_v = 0;}
if (!defined $opt_vv) {$opt_vv = 0;}
if (!defined $opt_txt) {$opt_txt = 0;}
if (!defined $opt_lst) {$opt_lst = 0;}

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

if (defined $opt_txt) {
   $opt_txt_tsitdesc = "QA1CSITF.DB.TXT";
   $opt_txt_tname =    "QA1DNAME.DB.TXT";
}
if (defined $opt_lst) {
   $opt_lst_tsitdesc = "QA1CSITF.DB.LST";
   $opt_lst_tsitdesc1 = "QA1CSITF1.DB.LST";
   $opt_lst_tname =    "QA1DNAME.DB.LST";
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
my @seg = ();
my @seg_time = ();
my $segi = -1;
my $segp = -1;
my $segcur = "";
my $segline;
my $segmax = 0;
my $skipzero = 0;
my $key;

my $advisori = -1;
my @advisor = ();

if ($logfn eq "") {
   $pattern = "_ms(_kdsmain)?\.inv";
   @results = ();
   opendir(DIR,$opt_logpath) || die("cannot opendir $opt_logpath: $!\n"); # get list of files
   @results = grep {/$pattern/} readdir(DIR);
   closedir(DIR);
   die "No _ms.inv found\n" if $#results == -1;
   if ($#results > 0) {         # more than one inv file - complain and exit
      $invlist = join(" ",@results);
      die "multiple invfiles [$invlist] - only one expected\n";
   }
   $logfn =  $results[0];
}


$full_logfn = $opt_logpath . $logfn;
if ($logfn =~ /.*\.inv$/) {
   open(INV, "< $full_logfn") || die("Could not open inv  $full_logfn\n");
   $inline = <INV>;
   die "empty INV file $full_logfn\n" if !defined $inline;
   $inline =~ s/\\/\//g;    # switch to forward slashes, less confusing when programming both environments
   $pos = rindex($inline,'/');
   $inline = substr($inline,$pos+1);
   $inline =~ m/(.*)-\d\d\.log$/;
   $inline =~ m/(.*)-\d\.log$/ if !defined $1;
   die "invalid log form $inline from $full_logfn\n" if !defined $1;
   $logbase = $1;
   $logfn = $1 . '-*.log';
   close(INV);
}


if (!defined $logbase) {
   $logbase = $logfn if ! -e $logfn;
}

sub open_kib;
sub read_kib;

my $pos;

open_kib();


if ($opt_z == 1) {$state = 1}

$inrowsize = 0;

for(;;)
{
   read_kib();
   if (!defined $inline) {
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
   if ($state == 0) {                       # state = 0 distributed log - no filtering
      $oneline = $inline;
   }
   elsif ($state == 1) {                       # state 1 - detect print or disk version of sysout file
      $offset = (substr($inline,0,1) eq "1") || (substr($inline,0,1) eq " ");
      $state = 2;
      $lagline = "";
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
   elsif ($state == 3) {                    # state 3 = potentially collect next part of line
      # case 1 - look for the + sign which means a second line of trace output
      #   emit data and resume looking for more
      if (substr($inline,21+$offset,1) eq "+") {
         next if $lagline eq "";
         $oneline = $lagline;
         $logtime = $lagtime;
         $lagline = "";
         $lagtime = 0;
         $laglocus = "";
         $state = 2;
         # fall through and process $oneline
      }
      # case 2 - line too short for a locus
      #          Append data to lagline and move on
      elsif (length($inline) < 35 + $offset) {
         $lagline .= " " . substr($inline,21+$offset);
         $state = 3;
         next;
      }

      # case 3 - line has an apparent locus, emit laggine line
      #          and continue looking for data to append to this new line
      elsif ((substr($inline,21+$offset,1) eq '(') &&
             (substr($inline,26+$offset,1) eq '-') &&
             (substr($inline,35+$offset,1) eq ':') &&
             (substr($inline,0+$offset,2) eq '20')) {
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

      # case 4 - Identify and ignore lines which appear to be z/OS operations log entries
      else {

         $oplogid = substr($inline,21+$offset,7);
         $oplogid =~ s/\s+$//;
         if (index($oplogid," ") == -1) {
             if((substr($oplogid,0,1) eq "K") ||
                (substr($oplogid,0,1) eq "O")) {
                next;
             }
         }
         next if substr($oplogid,0,3) eq "OM2";
         $lagline .= substr($inline,21+$offset);
         $state = 3;
         next;
      }
   }
   else {                   # should never happen
      print STDERR $oneline . "\n";
      die "Unknown state [$state] working on log $logfn at $l\n";
      next;
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
      $locus =~ /\((.*)-(.*):(.*)\,\"(.*)\"\)/;
      $logline = 0;      ##???
      $logthread = "T" . $1;
      $logunit = $2;
      $logentry = $3;
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
         $itable = $2;
         $isittype = $3;
         $iinterval = $4;
         $irowsize = $5;
         my $ht_ref = $hsitdata{$isitname};
         if (!defined $ht_ref) {
            my %htref = (
                           sitname => $isitname,
                           table => $itable,
                           type => $isittype,
                           rowsize => $irowsize,
                           interval => $iinterval,
                        );
            $hsitdata{$isitname} = \%htref;
            $tabsize{$itable} = $irowsize if !defined $tabsize{$itable};
         }
         $sitevalx{$isitname} = $iinterval if !defined $sitevalx{$isitname};
         $sitrowx{$isitname} = $irowsize if !defined $sitrowx{$isitname};
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
                     if (substr($isitname,0,8) ne "UADVISOR") {
                        # calculate sends for sampled situations

                        my $send_ref = $sendx{$isitname};
                        if (!defined $send_ref) {
                           my %sendref = (
                                            count => 0,
                                            table => $sitref->{table},
                                            reeval => 0,
                                            rowsize => 0,
                                            sends => [],
                                         );
                           $send_ref = \%sendref;
                           $sendx{$isitname} = \%sendref;
                        }
                        my %sender = (
                                        time => $cap_ref->{time_send},
                                        rows => $cap_ref->{sent},
                                        l => $l,
                                     );
                        push (@{$send_ref->{sends}},\%sender);
                        $send_ref->{count} += 1;
                     }
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
         $rest = $2;
         next if substr($rest,1,9) ne "Situation";
         if (substr($rest,1,11) eq "Situation  ") { #  Situation  <319817449,930087892> expired at 1433440014 and will next expire at 1433440194 : timeTaken = 2
            $rest =~ / Situation  <(.*?)> expired at (\d+) and will next expire at (\d+) .*? timeTaken = (\d+)/;
            $isitname = "*REALTIME";
            $iobjid = $1;
            $iexpire = $2;
            $inext = $3;
            $itaken = $4;
         } else {                                   #  Situation IBM_test_boa <1362101196,1339032516> expired at 1411502832 and will next expire at 1411502862 : timeTaken = 0
            $rest =~ / Situation (\S+) <(.*?)> expired at (\d+) and will next expire at (\d+) .*? timeTaken = (\d+)/;
            $isitname = $1;
            $iobjid = $2;
            $iexpire = $3;
            $inext = $4;
            $itaken = $5;
            $sitevalx{$isitname} = $inext - $iexpire if !defined $sitevalx{$isitname};
         }
         $ithread = $logthread;
         $sitref = $sitrun{$iobjid};
         if (defined $sitref) {
            $sitref->{state} = 2;                     # waiting for next DriveDataCollection
            $sitref->{coltime} += $itaken;            # time in data collection
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

$sit_duration = $sit_end - $sit_start;
$sit_duration = 1 if $sit_duration == 0;
$tdur = $trcetime - $trcstime;
$tdur = 1 if $tdur == 0;

foreach my $f (keys %sendx) {
   my $send_ref = $sendx{$f};
   my $ht_ref = $hsitdata{$f};
   if (defined $ht_ref) {
      $send_ref->{reeval} = $ht_ref->{interval};
      $send_ref->{rowsize} = $ht_ref->{rowsize};
   } else {
      $send_ref->{reeval} = $sitevalx{$f} if defined $sitevalx{$f};
      $send_ref->{rowsize} = $sitrowx{$f} if defined $sitrowx{$f};
   }
   if ($send_ref->{rowsize} == 0) {
      my $itable = $send_ref->{table};
      $send_ref->{rowsize} = $htabsize{$itable} if defined $htabsize{$itable};
   }
   if ($f eq "HEARTBEAT") {
      $send_ref->{reeval} = 600 if $send_ref->{reeval} == 0;
      $send_ref->{rowsize} = 220 if $send_ref->{rowsize} == 0;
      next;
   }
}


my $sittabi = -1;
my @sittab  = ();
my %sittabx = ();
my %sittabxx = ();
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
   $sittab_ref = $sittabx{$key};
   if (!defined $sittab_ref) {
      my %sittabref = (
                         sit => $sitref->{sitname},
                         tab => $sitref->{table},
                         instance => 0,
                         sendrows => 0,
                         sendtime => 0,
                         colct => 0,
                         colrows => 0,
                         colbytes => 0,
                         colfilt => 0,
                         coltime => 0,
                         rowsize => 0,
                         objid => "",
                         delayeval => 0,
                         delaysample => 0,
                         delaysend => 0,
                      );
      $sittab_ref = \%sittabref;
      $sittabx{$key} = \%sittabref;
   }
   $sittab_ref->{instance} += 1;
   $sittab_ref->{sendrows} += $sitref->{sendrows};
   $sittab_ref->{sendtime} += $sitref->{sendtime};
   $sittab_ref->{colct} += $sitref->{colcount};
   $sittab_ref->{colrows} += $sitref->{colrows};
   $sittab_ref->{colfilt} += $sitref->{colfilt};
   $sittab_ref->{coltime} += $sitref->{coltime};
   $sittab_ref->{rowsize} = $sitref->{rowsize} if defined $sitref->{rowsize};
   $sittab_ref->{objid} .=  "\"" . $sitref->{objid} . "\"",;
   $sittab_ref->{delayeval} += $sitref->{delayeval};
   $sittab_ref->{delaysample} += $sitref->{delaysample};
   $sittab_ref->{delaysend} += $sitref->{delaysend};
}

# If no data was ever sent to the TEMS, the trace record will have no information
# about row size. Row size is the number of bytes of data sent from the agent to
# the TEMS and is an important clue for how much data is being processed.

# First collect rowsize information when available.

my %htabsum = ();                             # a hash of table name to row size

foreach my $s ( keys %sittabx) {
   my $sittab_ref = $sittabx{$s};
   next if $sittab_ref->{rowsize} == 0;
   next if $sittab_ref->{tab} eq "";
   $htabsum{$sittab_ref->{tab}} = $sittab_ref->{rowsize};
}

# Review records with a zero row size and use if found from just calculated

foreach my $s ( keys %sittabx) {
   my $sittab_ref = $sittabx{$s};
   next if $sittab_ref->{rowsize} > 0;
   next if $sittab_ref->{tab} eq "";
   my $looksize = $htabsum{$sittab_ref->{tab}};
   next if !defined $looksize;
   $sittab_ref->{rowsize} = $looksize;
}

# For any cases that are still missing, reference a built in table of rowsizes.

foreach my $s ( keys %sittabx) {
   my $sittab_ref = $sittabx{$s};
   if ( $sittab_ref->{rowsize} > 0) {
      $sittab_ref->{colbytes} = $sittab_ref->{colrows} * $sittab_ref->{rowsize};
      next;
   }
   next if $sittab_ref->{tab} eq "";
   my $looksize = $htabsize{$sittab_ref->{tab}};
   next if !defined $looksize;
   $sittab_ref->{rowsize} = $looksize;
   $sittab_ref->{colbytes} = $sittab_ref->{colrows} * $sittab_ref->{rowsize};
   $htabsum{$sittab_ref->{tab}} = $looksize;
}

# calculate totals

foreach my $s ( keys %sittabx) {
   my $sittab_ref = $sittabx{$s};
   $sittab_total_coltime +=  $sittab_ref->{coltime};
   $sittab_total_colrows +=  $sittab_ref->{colrows};
   $sittab_total_colbytes +=  $sittab_ref->{colbytes};
}

my $sittab_cum_coltime = 0;
my $respc;
my $ppc;

my $pure_ct = 0;
$pure_dur = $pure_end - $pure_start;
$pure_dur = 1 if $pure_dur == 0;
$cnt++;$oline[$cnt]="Agent Workload Audit Report by Pure Situation and Table sorted by Filtered Rows\n";
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

my %sumcolx;

$cnt++;$oline[$cnt]="\n";
$cnt++;$oline[$cnt]="Agent Workload Audit Report by Sampled Situation and Table sorted by Collection Time\n";
$cnt++;$oline[$cnt]="\n";
$cnt++;$oline[$cnt]="Situation,Table,Time_Taken,TT%,TT%cum,Instance,Collections,Sendrows,Sendtime,Collect_Rows,Collect_Filter,Collect_Bytes,Row_Size,Delay_Eval,DelaySample,Delay_Send,Taken_Per_Collection\n";
foreach my $f ( sort { $sittabx{$b}->{coltime} <=> $sittabx{$a}->{coltime} or
                       $a cmp $b
                     } keys %sittabx ) {
   my $sittab_ref = $sittabx{$f};
#  next if $sittab_sit[$i] eq "dummysit";
   $outl = $sittab_ref->{sit} . ",";
   $outl .= $sittab_ref->{tab} . ",";
   $outl .= $sittab_ref->{coltime} . ",";
   $sittab_cum_coltime += $sittab_ref->{coltime};
   $res_pc = 0;
   $res_pc = int(($sittab_ref->{coltime}*100)/$sittab_total_coltime) if $sittab_total_coltime > 0;
   $ppc = sprintf '%.0f%%', $res_pc;
   $outl .= $ppc . ",";
   $res_pc = 0;
   $res_pc = int(($sittab_cum_coltime*100)/$sittab_total_coltime) if $sittab_total_coltime > 0;
   $ppc = sprintf '%.0f%%', $res_pc;
   $outl .= $ppc . ",";
   $outl .= $sittab_ref->{instance} . ",";
   $outl .= $sittab_ref->{colct} . ",";
   $outl .= $sittab_ref->{sendrows} . ",";
   $outl .= $sittab_ref->{sendtime} . ",";
   $outl .= $sittab_ref->{colrows} . ",";
   $outl .= $sittab_ref->{colfilt} . ",";
   $outl .= $sittab_ref->{colbytes} . ",";
   $outl .= $sittab_ref->{rowsize} . ",";
   $outl .= $sittab_ref->{delayeval} . ",";
   $outl .= $sittab_ref->{delaysample} . ",";
   $outl .= $sittab_ref->{delaysend} . ",";
   $res_pc = int($sittab_ref->{coltime}/$sittab_ref->{colct}) if $sittab_ref->{colct} > 0;
   $ppc = sprintf '%.0f', $res_pc;
   $outl .= $ppc . ",";
   $outl .= $sittab_ref->{objid} . "," if $opt_objid == 1;
   $cnt++;$oline[$cnt]="$outl\n";
   if ($sittab_ref->{colct} > 0) {
      if ($sittab_ref->{coltime} > 0) {
         my $timeper = $sittab_ref->{coltime} / $sittab_ref->{colct};
         my %sumcoldef = (
                            colper => $sittab_ref->{coltime} / $sittab_ref->{colct},
                            sendper => $sittab_ref->{sendrows} / $sittab_ref->{colct},
                            rowsize => $sittab_ref->{rowsize},
                         );
         $sumcolx{$sittab_ref->{sit}} = \%sumcoldef;
      }
   }
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
foreach my $f ( sort { $sittabx{$b}->{colbytes} <=> $sittabx{$a}->{colbytes} or
                       $a cmp $b
                     } keys %sittabx ) {
   my $sittab_ref = $sittabx{$f};
#  next if $sittab_sit[$i] eq "dummysit";
   $outl = $sittab_ref->{sit} . ",";
   $outl .= $sittab_ref->{tab} . ",";
   $outl .= $sittab_ref->{coltime} . ",";
   $outl .= $sittab_ref->{instance} . ",";
   $outl .= $sittab_ref->{colct} . ",";
   $outl .= $sittab_ref->{sendrows} . ",";
   $outl .= $sittab_ref->{sendtime} . ",";
   $outl .= $sittab_ref->{colrows} . ",";
   $outl .= $sittab_ref->{colfilt} . ",";
   $outl .= $sittab_ref->{colbytes} . ",";
   $res_pc = 0;
   $res_pc = int(($sittab_ref->{colbytes}*100)/$sittab_total_colbytes)  if $sittab_total_colbytes > 0;
   $ppc = sprintf '%.0f%%', $res_pc;
   $outl .= $ppc . ",";
   $sittab_cum_colbytes += $sittab_ref->{colbytes};
   $res_pc = 0;
   $res_pc = int(($sittab_cum_colbytes*100)/$sittab_total_colbytes)  if $sittab_total_colbytes > 0;
   $ppc = sprintf '%.0f', $res_pc;
   $outl .= $ppc . "%,";
   $outl .= $sittab_ref->{rowsize} . ",";
   $outl .= $sittab_ref->{delayeval} . ",";
   $outl .= $sittab_ref->{delaysample} . ",";
   $outl .= $sittab_ref->{delaysend} . ",";
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

# first Goal is to detect long delayed SendData rows
my $send_ct = scalar keys %sendx;
my $send_ctt = 0;
if ($send_ct > 0) {
   foreach my $f (keys %sendx) {
      next if $f eq "*REALTIME";
      $send_ref = $sendx{$f};
      next if $send_ref->{count} <= 1;
      my $ht_ref = $hsitdata{$f};
      my $sends_state = 0;   # waiting for a SendData
      my $sends_ref;
      my $prior_sendsr_ref;
      my $ireeval = $sitevalx{$f};
      next if !defined $ireeval;
      foreach my $g (@{$send_ref->{sends}}) {
         my $sends_ref = $g;
         if ($sends_state == 0) {
            next if $sends_ref->{rows} == 0;
            $sends_state = 1;
         } elsif($sends_state == 1 ) {
            my $elapsed = $sends_ref->{time} - $prior_sends_ref->{time};
            $send_ctt += 1 if $elapsed > 3* $ireeval;      # delay time exceeds 3*sampling interval
            $sends_state = 0 if $sends_ref->{rows} == 0;
         }
         $prior_sends_ref = $sends_ref;
      }
   }
}

if ($send_ctt > 0) {
   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="SendData Delay Report\n";
   $cnt++;$oline[$cnt]="Situation,Reeval,Delay,Prior_Time,Prior_Rows,Prior_Line,Curr_time,Curr_Rows,Curr_Line,\n";
   foreach my $f (keys %sendx) {
      next if $f eq "*REALTIME";
      $send_ref = $sendx{$f};
      next if $send_ref->{count} <= 1;
      my $sends_state = 0;   # waiting for a SendData
      my $sends_ref;
      my $prior_sendsr_ref;
      my $ireeval = $sitevalx{$f};
      next if !defined $ireeval;
      foreach my $g (@{$send_ref->{sends}}) {
         my $sends_ref = $g;
         if ($sends_state == 0) {
            next if $sends_ref->{rows} == 0;
            $sends_state = 1;
         } elsif($sends_state == 1 ) {
            if ($sends_ref->{rows} > 0) {
               my $elapsed = $sends_ref->{time} - $prior_sends_ref->{time};
               if ($elapsed > 3*$ireeval) {
                  $outline = $f . ",";
                  $outline .= $ireeval . ",";
                  $outline .= $elapsed . ",";
                  $outline .= $sends_ref->{time} . ",";
                  $outline .= $sends_ref->{rows} . ",";
                  $outline .= $sends_ref->{l} . ",";
                  $outline .= $prior_sends_ref->{time} . ",";
                  $outline .= $prior_sends_ref->{rows} . ",";
                  $outline .= $prior_sends_ref->{l} . ",";
                  $cnt++;$oline[$cnt]="$outline,\n";
               }
            }
            $sends_state = 0 if $sends_ref->{rows} == 0;
         }
         $prior_sends_ref = $sends_ref;
      }
   }
}


#
# Goal is to do a run through of 24 hours and determine how much Taken will be
# needed for all sampled situations.
my $sittab_ct = scalar keys %sittabx;
if ($sittab_ct > 0) {
   my $colday_total = 0;
   my $colday_cummulative = 0;
   foreach my $f ( sort {$a cmp $b} keys %sittabx) {
      my $sittab_ref = $sittabx{$f};
      $sittab_ref->{cycle} = 0;
      $sittab_ref->{colday} = 0;
      $sittab_ref->{colbytesday} = 0;
      my $isitname = $sittab_ref->{sit};
      my $col_ref = $sumcolx{$isitname};
      next if !defined $col_ref;
      next if $col_ref->{colper} == 0;
      my $ireeval = $sitevalx{$isitname};
      next if !defined $ireeval;
      next if $ireeval == 0;
      $sittab_ref->{cycle} = 86400 / $ireeval;
      $sittab_ref->{colday} = $col_ref->{colper} * $sittab_ref->{cycle};
      $colday_total +=  $sittab_ref->{colday};
      $sittab_ref->{colbytesday} = $col_ref->{colper} * $sittab_ref->{cycle} * $col_ref->{rowsize};
   }
   $cnt++;$oline[$cnt]="\n";
   $cnt++;$oline[$cnt]="TimeTaken over 24 hours - sorted descending by time per day\n";
   $cnt++;$oline[$cnt]="Situation,Time_Taken,TT%,CumTT%,Table,Reeval,Rowsize,Collects/Day,,Bytes/Day,\n";
   foreach my $f ( sort { $sittabx{$b}->{colday} <=> $sittabx{$a}->{colday} or
                          $a cmp $b
                        } keys %sittabx ) {
      my $sittab_ref = $sittabx{$f};
      my $isitname = $sittab_ref->{sit};
      my $col_ref = $sumcolx{$isitname};
      next if !defined $col_ref;
      next if $col_ref->{colper} == 0;
      my $ireeval = $sitevalx{$isitname};
      next if !defined $ireeval;
      next if $ireeval == 0;
      $colday_cummulative +=  $sittab_ref->{colday};
      $outline = $sittab_ref->{sit} . ",";
      $outline .= $sittab_ref->{colday} . ",";
      $res_pc = 0;
      $res_pc = int(($sittab_ref->{colday}*100)/$colday_total) if $colday_total > 0;
      $ppc = sprintf '%.0f%%', $res_pc;
      $outline .= $ppc . ",";
      $res_pc = 0;
      $res_pc = int(($colday_cummulative*100)/$colday_total) if $colday_total > 0;
      $ppc = sprintf '%.0f%%', $res_pc;
      $outline .= $ppc . ",";
      $outline .= $sittab_ref->{tab} . ",";
      $outline .= $ireeval . ",";
      $outline .= $col_ref->{rowsize} . ",";
      $outline .= $sittab_ref->{cycle} . ",";
      $outline .= $sittab_ref->{colbytes} . ",";
      $cnt++;$oline[$cnt]="$outline\n";
   }
   $outline = "*total" . ",";
   $outline .= $colday_total . ",";
   $cnt++;$oline[$cnt]="$outline\n";
}



open OH, ">$opt_o" or die "can't open $opt_o: $!";

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

exit 0;


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
         if ($tgot == 0) {
            print STDERR "the log $dlog ignored, did not have a timestamp in the first $tlimit lines.\n";
            next;
         }
         $todo{$dlog} = hex($itime);               # Add to array of logs
         close($dh);
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
# 0.88000 - Reset to just TEMA Flow and add send delays and 24 hour estimate report
