$ntpserver= "0.ru.pool.ntp.org"
$etrserver= "10.248.35.9"
$win10build="1709"

######Funkciya proverki portov do 274 stroki
function Test-Port{   
<#     
.SYNOPSIS     
    Tests port on computer.   
     
.DESCRIPTION   
    Tests port on computer.  
      
.PARAMETER computer   
    Name of server to test the port connection on. 
       
.PARAMETER port   
    Port to test  
        
.PARAMETER tcp   
    Use tcp port  
       
.PARAMETER udp   
    Use udp port   
      
.PARAMETER UDPTimeOut  
    Sets a timeout for UDP port query. (In milliseconds, Default is 1000)   
       
.PARAMETER TCPTimeOut  
    Sets a timeout for TCP port query. (In milliseconds, Default is 1000) 
                  
.NOTES     
    Name: Test-Port.ps1   
    Author: Boe Prox   
    DateCreated: 18Aug2010    
    List of Ports: http://www.iana.org/assignments/port-numbers   
       
    To Do:   
        Add capability to run background jobs for each host to shorten the time to scan.          
.LINK     
    https://boeprox.wordpress.org  
      
.EXAMPLE     
    Test-Port -computer 'server' -port 80   
    Checks port 80 on server 'server' to see if it is listening   
     
.EXAMPLE     
    'server' | Test-Port -port 80   
    Checks port 80 on server 'server' to see if it is listening  
       
.EXAMPLE     
    Test-Port -computer @("server1","server2") -port 80   
    Checks port 80 on server1 and server2 to see if it is listening   
     
.EXAMPLE 
    Test-Port -comp dc1 -port 17 -udp -UDPtimeout 10000 
     
    Server   : dc1 
    Port     : 17 
    TypePort : UDP 
    Open     : True 
    Notes    : "My spelling is Wobbly.  It's good spelling but it Wobbles, and the letters 
            get in the wrong places." A. A. Milne (1882-1958) 
     
    Description 
    ----------- 
    Queries port 17 (qotd) on the UDP port and returns whether port is open or not 
        
.EXAMPLE     
    @("server1","server2") | Test-Port -port 80   
    Checks port 80 on server1 and server2 to see if it is listening   
       
.EXAMPLE     
    (Get-Content hosts.txt) | Test-Port -port 80   
    Checks port 80 on servers in host file to see if it is listening  
      
.EXAMPLE     
    Test-Port -computer (Get-Content hosts.txt) -port 80   
    Checks port 80 on servers in host file to see if it is listening  
         
.EXAMPLE     
    Test-Port -computer (Get-Content hosts.txt) -port @(1..59)   
    Checks a range of ports from 1-59 on all servers in the hosts.txt file       
             
#>    
[cmdletbinding(   
    DefaultParameterSetName = '',   
    ConfirmImpact = 'low'   
)]   
    Param(   
        [Parameter(   
            Mandatory = $True,   
            Position = 0,   
            ParameterSetName = '',   
            ValueFromPipeline = $True)]   
            [array]$computer,   
        [Parameter(   
            Position = 1,   
            Mandatory = $True,   
            ParameterSetName = '')]   
            [array]$port,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [int]$TCPtimeout=1000,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [int]$UDPtimeout=1000,              
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [switch]$TCP,   
        [Parameter(   
            Mandatory = $False,   
            ParameterSetName = '')]   
            [switch]$UDP                                     
        )   
    Begin {   
        If (!$tcp -AND !$udp) {$tcp = $True}   
        #Typically you never do this, but in this case I felt it was for the benefit of the function   
        #as any errors will be noted in the output of the report           
        $ErrorActionPreference = "SilentlyContinue"   
        $report = @()   
    }   
    Process {      
        ForEach ($c in $computer) {   
            ForEach ($p in $port) {   
                If ($tcp) {     
                    #Create temporary holder    
                    $temp = "" | Select Server, Port, TypePort, Open, Notes   
                    #Create object for connecting to port on computer   
                    $tcpobject = new-Object system.Net.Sockets.TcpClient   
                    #Connect to remote machine's port                 
                    $connect = $tcpobject.BeginConnect($c,$p,$null,$null)   
                    #Configure a timeout before quitting   
                    $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false)   
                    #If timeout   
                    If(!$wait) {   
                        #Close connection   
                        $tcpobject.Close()   
                        Write-Verbose "Connection Timeout"   
                        #Build report   
                        $temp.Server = $c   
                        $temp.Port = $p   
                        $temp.TypePort = "TCP"   
                        $temp.Open = "False"   
                        $temp.Notes = "Connection to Port Timed Out"   
                    } Else {   
                        $error.Clear()   
                        $tcpobject.EndConnect($connect) | out-Null   
                        #If error   
                        If($error[0]){   
                            #Begin making error more readable in report   
                            [string]$string = ($error[0].exception).message   
                            $message = (($string.split(":")[1]).replace('"',"")).TrimStart()   
                            $failed = $true   
                        }   
                        #Close connection       
                        $tcpobject.Close()   
                        #If unable to query port to due failure   
                        If($failed){   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "TCP"   
                            $temp.Open = "False"   
                            $temp.Notes = "$message"   
                        } Else{   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "TCP"   
                            $temp.Open = "True"     
                            $temp.Notes = ""   
                        }   
                    }      
                    #Reset failed value   
                    $failed = $Null       
                    #Merge temp array with report               
                    $report += $temp   
                }       
                If ($udp) {   
                    #Create temporary holder    
                    $temp = "" | Select Server, Port, TypePort, Open, Notes                                      
                    #Create object for connecting to port on computer   
                    $udpobject = new-Object system.Net.Sockets.Udpclient 
                    #Set a timeout on receiving message  
                    $udpobject.client.ReceiveTimeout = $UDPTimeout  
                    #Connect to remote machine's port                 
                    Write-Verbose "Making UDP connection to remote server"  
                    $udpobject.Connect("$c",$p)  
                    #Sends a message to the host to which you have connected.  
                    Write-Verbose "Sending message to remote host"  
                    $a = new-object system.text.asciiencoding  
                    $byte = $a.GetBytes("$(Get-Date)")  
                    [void]$udpobject.Send($byte,$byte.length)  
                    #IPEndPoint object will allow us to read datagrams sent from any source.   
                    Write-Verbose "Creating remote endpoint"  
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0)  
                    Try {  
                        #Blocks until a message returns on this socket from a remote host.  
                        Write-Verbose "Waiting for message return"  
                        $receivebytes = $udpobject.Receive([ref]$remoteendpoint)  
                        [string]$returndata = $a.GetString($receivebytes) 
                        If ($returndata) { 
                           Write-Verbose "Connection Successful"   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "UDP"   
                            $temp.Open = "True"   
                            $temp.Notes = $returndata    
                            $udpobject.close()    
                        }                        
                    } Catch {  
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") {  
                            #Close connection   
                            $udpobject.Close()   
                            #Make sure that the host is online and not a false positive that it is open  
                            If (Test-Connection -comp $c -count 1 -quiet) {  
                                Write-Verbose "Connection Open"   
                                #Build report   
                                $temp.Server = $c   
                                $temp.Port = $p   
                                $temp.TypePort = "UDP"   
                                $temp.Open = "True"   
                                $temp.Notes = ""  
                            } Else {  
                                <#  
                                It is possible that the host is not online or that the host is online,   
                                but ICMP is blocked by a firewall and this port is actually open.  
                                #>  
                                Write-Verbose "Host maybe unavailable"   
                                #Build report   
                                $temp.Server = $c   
                                $temp.Port = $p   
                                $temp.TypePort = "UDP"   
                                $temp.Open = "False"   
                                $temp.Notes = "Unable to verify if port is open or if host is unavailable."                                  
                            }                          
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {  
                            #Close connection   
                            $udpobject.Close()   
                            Write-Verbose "Connection Timeout"   
                            #Build report   
                            $temp.Server = $c   
                            $temp.Port = $p   
                            $temp.TypePort = "UDP"   
                            $temp.Open = "False"   
                            $temp.Notes = "Connection to Port Timed Out"                          
                        } Else {                       
                            $udpobject.close()  
                        }  
                    }      
                    #Merge temp array with report               
                    $report += $temp   
                }                                   
            }   
        }                   
    }   
    End {   
        #Generate Report   
        $report  
    } 
}


"Работает ЭВМM... zhdite..."
###SLUZHBA BRANDMAUEHRA
$servicefw=Get-Service mpssvc #zapros statusa sluzhby brandmauehra

###VERSIYA OS
$ver_major=[Environment]::OSVersion.Version.Major
$ver_minor=[Environment]::OSVersion.Version.Minor
if ($ver_major -eq "6" -and $ver_minor -lt "3") {$ver="old"}
if ($ver_major -eq "6" -and $ver_minor -eq "3") {$ver="new"}
if ($ver_major -eq "10") {$ver="new"}


###PROVERKA VREMENI
$date = (Get-Date).ToString('dd MMMM yyyyg.') #poluchit' datu
$time = (Get-Date).ToString('HH:mm') #poluchit' vremya v formate 24h
$timezone=[TimeZoneInfo]::Local.DisplayName | %{ $_.Split(" ")[0]; } #poluchit' chasovoj poyas i ubrat' vse lishnee, krome UTC*


$dirtytimentp=w32tm /stripchart /computer:$ntpserver /samples:3 #zaprosit' ntp server tekushchee vremya
[string]$timentp=$dirtytimentp[5] #vydelit' stroku s otvetom servera
$checkntp=$timentp.IndexOf("d:") #proverka otklika ntp servera
#$timenew= $timentp.Substring(0,8) #vydelit' tekushchee vremya
if ($checkntp -ne "-1") #esli ntp server dostupen
{
$timentp= $timentp.Split(":")[4] #vydelit' smeshchenie vremeni k ehtalonnomu serveru NTP
$timentp= $timentp.Split(".")[0] #ubrat' iz smeshcheniya cifry posle zapyatoj.
[int]$timentp= $timentp.Substring(1.) #vzyat' modul' ot chisla.
}
else #esli Ntp server ne dostupen
{
[int]$timentp=-1
}
#v zavisimosti ot raskhozhdeniya vremeni sgenerirovat' soobshchenie
if ($timentp -lt "60") {$count_time="1"; $message_time="Vremya na komp'yutere sootvetstvuet serveru $ntpserver"}
if ($timentp -ge "60" -and $timenet -lt "3600") {$count_time="2"; $message_time="Vremya na komp'yutere otlichaetsya ot servera $ntpserver v predelah odnogo chasa"}
if ($timentp -ge "3600" -and $timentp -lt "86400") {$count_time="3"; $message_time="Vremya na komp'yutere otlichaetsya ot servera $ntpserver bolee chem na odin chas"}
if ($timentp -ge "86400") {$count_time="4";  $message_time="Data na komp'yutere olichaetsya ot servera $ntpserver"}
if ($timentp -eq "-1") {$count_time="5"; $message_time="Server vremeni $ntpserver nedostupen, prover'te datu i vremya vruchnuyu"}

###PROVERKA IE

$IE=Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" #vetka s nastrojkami IE
$IEProxy=$IE.DefaultConnectionSettings[8] #parametr nastrojki proksi

###PROVERKA KOORDINATORA
[string]$reg_vipnet= get-process | where {$_.ProcessName -eq 'monitor'} | Get-ChildItem

if (!$reg_vipnet){} #Esli process ne zapushchen, to proverku koordinatora provodit' ne pytat'sya
else
{
#$path_vipnet= $reg_vipnet -Split "\\Monitor.exe" #najti katalog s vipnet
$path_vipnet= $reg_vipnet -replace "\\Monitor.exe"  #najti katalog s vipnet
[string]$vipnet= get-content "$path_vipnet\APN*.TXT" | select-string "0000 S S " #najti v fajle koordinator, za kotorym zaveden AP
$name_coord_vipnet= $vipnet.Substring(9,51) #vydelit' imya koordinatora s probelami v konce imeni
$name_coord_vipnet= $name_coord_vipnet -replace "  " #vydelit' imya koordinatora bez probelami
$id_coord_vipnet= $vipnet.Substring(60,9) #najti Id koordinatora
$id2_coord_vipnet= $vipnet.Substring(74,12)  #####neponyatki s kolichestvom nulej. v fajle ipliradr.do$ dva ili chetyre nulya?
[string]$ip_coord_vipnet= get-content "$path_vipnet\fireaddr.doc" | Select-String -Pattern $id_coord_vipnet |%{($_ -split "[ ]")[1]} #najti ip-koordinatora
#$vipnet2= Test-NetConnection -ComputerName $ip_coord_vipnet
$vipnet2= Test-Connection $ip_coord_vipnet -count 2 -quiet -ErrorAction SilentlyContinue #proverit' soedinenie s koordinatorom
}

###PROVERKA NALICHIYA TUNNELYA
$tun1_coord_vipnet= get-content "$path_vipnet\ipliradr.do$" | Select-String -Pattern $id2_coord_vipnet | Select-String -Pattern " S:" | Select-String -NotMatch "-" |%{($_ -split "[ S:]")[4]}
$tun2_coord_vipnet= get-content "$path_vipnet\ipliradr.do$" | Select-String -Pattern $id2_coord_vipnet | Select-String -Pattern " S:" | Select-String -Pattern "-" |%{($_ -split "[ S:]")[4]}
$tun1_etran= $tun1_coord_vipnet | Select-String -Pattern $etrserver
foreach ($temp in $tun2_coord_vipnet) #cikl dlya postrochnogo chteniya
{
$x= $temp.Split("-")[0]
$y= $temp.Split("-")[1]
[int]$a1= $x.Split(".")[0]
[int]$b1= $x.Split(".")[1]
[int]$c1= $x.Split(".")[2]
[int]$d1= $x.Split(".")[3]
[int]$a2= $y.Split(".")[0]
[int]$b2= $y.Split(".")[1]
[int]$c2= $y.Split(".")[2]
[int]$d2= $y.Split(".")[3]

$ip1= ($a1*16777216)+($b1*65536)+($c1*256)+($d1)
$ip2= ($a2*16777216)+($b2*65536)+($c2*256)+($d2)
if ($ip1 -le "184034057" -and $ip2 -ge "184034057"){$tun2_etran= $etrserver }
}
if ($tun1_etran -eq "$etrserver" -or $tun2_etran -eq "$etrserver") {$tun_etran= "$etrserver"}

###PROVERKA EHTRANA
if ($tun_etran -eq "$etrserver" -and $vipnet2 -eq "True")
    {
    #$etran= Test-NetConnection -ComputerName 10.248.35.9 -Port 8092
    $etran= Test-Port -computer $etrserver -port 8092   
    }

###VYVOD REZUL'TATOV
write-host "---===PROVERKA VREMENNYH NASTROEK===---" -BackgroundColor White -ForegroundColor black
"Data        : " + $date
"Vremya       : " + $time
"CHasovoj poyas: " + $timezone
if ($count_time -eq "1") {Write-Host $message_time -BackgroundColor Green -ForegroundColor Black} 
if ($count_time -eq "2") {Write-Host $message_time -BackgroundColor Yellow -ForegroundColor Black} 
if ($count_time -gt "2" -and $count_time -lt "5") {Write-Host $message_time -BackgroundColor Red -ForegroundColor Black}
if ($count_time -eq "5") {Write-Host $message_time -BackgroundColor Yellow -ForegroundColor Black}
if ($timezone -eq "(UTC+03:00)") {Write-Host "CHasovoj poyas ustanovlen pravil'no" -BackgroundColor Green -ForegroundColor Black}
if ($timezone -ne "(UTC+03:00)") {Write-Host "CHasovoj poyas ustanovlen nepravil'no" -BackgroundColor Red -ForegroundColor Black}
""

write-host "---===PROVERKA BRANDMAUEHRA===---" -BackgroundColor White -ForegroundColor black
if ($servicefw.Status -eq "Stopped") {Write-Host "Sluzhba brandmauehra vyklyuchena" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Sluzhba brandmauehra vklyuchena" -BackgroundColor Red -ForegroundColor Black}
""
write-host "---===PROVERKA DOSTUPNOSTI KOORDINATORA===---" -BackgroundColor White -ForegroundColor black
if (!$reg_vipnet) {Write-Host "PO ViPNet Client ne ustanovleno ili ne zapushcheno" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($vipnet2 -eq "True") {Write-Host "Koordinator" $name_coord_vipnet $ip_coord_vipnet "dostupen" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Koordinator" $name_coord_vipnet $ip_coord_vipnet "nedostupen" -BackgroundColor Red -ForegroundColor Black}
}
""
write-host "---===PROVERKA NALICHIYA TUNNELYA DO AS EHTRAN===---" -BackgroundColor White -ForegroundColor black
if (!$reg_vipnet) {Write-Host "Ne udalos' obnaruzhit' zapushchennoe ili ustanovlennoe PO ViPNet Client" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($tun1_etran -eq "$etrserver" -or $tun2_etran -eq "$etrserver") {Write-Host "Tunnel' do" $etrserver "propisan" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Tunnel' do 10.248.35.9 otsutstvuet" -BackgroundColor Red -ForegroundColor Black}
}
""
write-host "---===PROVERKA NASTROEK BRAUZERA===---" -BackgroundColor White -ForegroundColor black
if ($IEProxy -eq "1") {Write-Host -BackgroundColor Green -ForegroundColor Black "Proksi-server v IE otklyuchen"}
if ($IEProxy -eq "3") {Write-Host -BackgroundColor Red -ForegroundColor Black "Proksi-server v IE vklyuchen"}
if ($IEProxy -eq "5" -or $IEProxy -eq "9") {Write-Host -BackgroundColor Yellow -ForegroundColor Black "Avtoopredelenie proksi-servera v IE vklyucheno"}
if ($IEProxy -ne "1" -and $IEProxy -ne "3" -and $IEProxy -ne "5" -and $IEProxy -ne "9") {Write-Host -BackgroundColor Yellow -ForegroundColor Black "Nastrojki IE opredelit' ne udalos' :("}
""
write-host "---===PROVERKA DOSTUPNOSTI AS EHTRAN===---" -BackgroundColor White -ForegroundColor black
if ($etran.Open -eq "True") {Write-Host "AS EHTRAN" $etrserver "dostupna" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "AS EHTRAN 10.248.35.9 nedostupna" -BackgroundColor Red -ForegroundColor Black}
if ($vipnet2 -eq "True" -and $IEProxy -eq "1" -and $etran.Open -ne "True")
    {
    if ($tun1_etran -eq "$etrserver" -or $tun2_etran -eq "$etrserver")
        {
        "Vozmozhnye prichiny:"
        "1. V nastrojkah PO ViPNet vyklyucheny tunneli;"
        "2. Tunneli nastroeny na raboty po virtual'nym adresam, dostup nuzhno proverit' vruchnuyuж"
        "4. Slomalsya EHTRAN.кирилЛИЦА"
        }
    }

