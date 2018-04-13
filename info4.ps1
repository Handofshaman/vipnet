$ntpserver= "0.ru.pool.ntp.org"
$etrserver= "10.248.35.9"
$win10build="1709"

######Функция проверки портов до 274 строки
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


"Работает ЭВМ... ждите..."
###СЛУЖБА БРАНДМАУЭРА
$servicefw=Get-Service mpssvc #запрос статуса службы брандмауэра

###ВЕРСИЯ ОС
$ver_major=[Environment]::OSVersion.Version.Major
$ver_minor=[Environment]::OSVersion.Version.Minor
if ($ver_major -eq "6" -and $ver_minor -lt "3") {$ver="old"}
if ($ver_major -eq "6" -and $ver_minor -eq "3") {$ver="new"}
if ($ver_major -eq "10") {$ver="new"}


###ПРОВЕРКА ВРЕМЕНИ
$date = (Get-Date).ToString('dd MMMM yyyyг.') #получить дату
$time = (Get-Date).ToString('HH:mm') #получить время в формате 24h
$timezone=[TimeZoneInfo]::Local.DisplayName | %{ $_.Split(" ")[0]; } #получить часовой пояс и убрать все лишнее, кроме UTC*


$dirtytimentp=w32tm /stripchart /computer:$ntpserver /samples:3 #запросить ntp сервер текущее время
[string]$timentp=$dirtytimentp[5] #выделить строку с ответом сервера
$checkntp=$timentp.IndexOf("d:") #проверка отклика ntp сервера
#$timenew= $timentp.Substring(0,8) #выделить текущее время
if ($checkntp -ne "-1") #если ntp сервер доступен
{
$timentp= $timentp.Split(":")[4] #выделить смещение времени к эталонному серверу NTP
$timentp= $timentp.Split(".")[0] #убрать из смещения цифры после запятой.
[int]$timentp= $timentp.Substring(1.) #взять модуль от числа.
}
else #если Ntp сервер не доступен
{
[int]$timentp=-1
}
#в зависимости от расхождения времени сгенерировать сообщение
#if ($timentp -lt "60") {$count_time="1"; $message_time="Время на компьютере соответствует серверу $ntpserver"}
#if ($timentp -ge "60" -and $timenet -lt "3600") {$count_time="2"; $message_time="Время на компьютере отличается от сервера $ntpserver в пределах одного часа"}
#if ($timentp -ge "3600" -and $timentp -lt "86400") {$count_time="3"; $message_time="Время на компьютере отличается от сервера $ntpserver более чем на один час"}
#if ($timentp -ge "86400") {$count_time="4";  $message_time="Дата на компьютере оличается от сервера $ntpserver"}
#if ($timentp -eq "-1") {$count_time="5"; $message_time="Сервер времени $ntpserver недоступен, проверьте дату и время вручную"}

###ПРОВЕРКА IE

$IE=Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" #ветка с настройками IE
$IEProxy=$IE.DefaultConnectionSettings[8] #параметр настройки прокси

###ПРОВЕРКА КООРДИНАТОРА
[string]$reg_vipnet= get-process | where {$_.ProcessName -eq 'monitor'} | Get-ChildItem

if (!$reg_vipnet){} #Если процесс не запущен, то проверку координатора проводить не пытаться
else
{
#$path_vipnet= $reg_vipnet -Split "\\Monitor.exe" #найти каталог с vipnet
$path_vipnet= $reg_vipnet -replace "\\Monitor.exe"  #найти каталог с vipnet
[string]$vipnet= get-content "$path_vipnet\APN*.TXT" | select-string "0000 S S " #найти в файле координатор, за которым заведен АП
$name_coord_vipnet= $vipnet.Substring(9,51) #выделить имя координатора с пробелами в конце имени
$name_coord_vipnet= $name_coord_vipnet -replace "  " #выделить имя координатора без пробелами
$id_coord_vipnet= $vipnet.Substring(60,9) #найти Id координатора
$id2_coord_vipnet= $vipnet.Substring(74,12)  #####непонятки с количеством нулей. в файле ipliradr.do$ два или четыре нуля?
[string]$ip_coord_vipnet= get-content "$path_vipnet\fireaddr.doc" | Select-String -Pattern $id_coord_vipnet |%{($_ -split "[ ]")[1]} #найти ip-координатора
#$vipnet2= Test-NetConnection -ComputerName $ip_coord_vipnet
$vipnet2= Test-Connection $ip_coord_vipnet -count 2 -quiet -ErrorAction SilentlyContinue #проверить соединение с координатором
}

###ПРОВЕРКА НАЛИЧИЯ ТУННЕЛЯ
$tun1_coord_vipnet= get-content "$path_vipnet\ipliradr.do$" | Select-String -Pattern $id2_coord_vipnet | Select-String -Pattern " S:" | Select-String -NotMatch "-" |%{($_ -split "[ S:]")[4]}
$tun2_coord_vipnet= get-content "$path_vipnet\ipliradr.do$" | Select-String -Pattern $id2_coord_vipnet | Select-String -Pattern " S:" | Select-String -Pattern "-" |%{($_ -split "[ S:]")[4]}
$tun1_etran= $tun1_coord_vipnet | Select-String -Pattern $etrserver
foreach ($temp in $tun2_coord_vipnet) #цикл для построчного чтения
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

###ПРОВЕРКА ЭТРАНА
if ($tun_etran -eq "$etrserver" -and $vipnet2 -eq "True")
    {
    #$etran= Test-NetConnection -ComputerName 10.248.35.9 -Port 8092
    $etran= Test-Port -computer $etrserver -port 8092   
    }

###ВЫВОД РЕЗУЛЬТАТОВ
write-host "---===ПРОВЕРКА ВРЕМЕННЫХ НАСТРОЕК===---" -BackgroundColor White -ForegroundColor black
"Дата        : " + $date
"Время       : " + $time
"Часовой пояс: " + $timezone
if ($count_time -eq "1") {Write-Host $message_time -BackgroundColor Green -ForegroundColor Black} 
if ($count_time -eq "2") {Write-Host $message_time -BackgroundColor Yellow -ForegroundColor Black} 
if ($count_time -gt "2" -and $count_time -lt "5") {Write-Host $message_time -BackgroundColor Red -ForegroundColor Black}
if ($count_time -eq "5") {Write-Host $message_time -BackgroundColor Yellow -ForegroundColor Black}
if ($timezone -eq "(UTC+03:00)") {Write-Host "Часовой пояс установлен правильно" -BackgroundColor Green -ForegroundColor Black}
if ($timezone -ne "(UTC+03:00)") {Write-Host "Часовой пояс установлен неправильно" -BackgroundColor Red -ForegroundColor Black}
""

write-host "---===ПРОВЕРКА БРАНДМАУЭРА===---" -BackgroundColor White -ForegroundColor black
if ($servicefw.Status -eq "Stopped") {Write-Host "Служба брандмауэра выключена" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Служба брандмауэра включена" -BackgroundColor Red -ForegroundColor Black}
""
write-host "---===ПРОВЕРКА ДОСТУПНОСТИ КООРДИНАТОРА===---" -BackgroundColor White -ForegroundColor black
if (!$reg_vipnet) {Write-Host "ПО ViPNet Client не установлено или не запущено" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($vipnet2 -eq "True") {Write-Host "Координатор" $name_coord_vipnet $ip_coord_vipnet "доступен" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Координатор" $name_coord_vipnet $ip_coord_vipnet "недоступен" -BackgroundColor Red -ForegroundColor Black}
}
""
write-host "---===ПРОВЕРКА НАЛИЧИЯ ТУННЕЛЯ ДО АС ЭТРАН===---" -BackgroundColor White -ForegroundColor black
if (!$reg_vipnet) {Write-Host "Не удалось обнаружить запущенное или установленное ПО ViPNet Client" -BackgroundColor Red -ForegroundColor Black}
else
{
if ($tun1_etran -eq "$etrserver" -or $tun2_etran -eq "$etrserver") {Write-Host "Туннель до" $etrserver "прописан" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "Туннель до 10.248.35.9 отсутствует" -BackgroundColor Red -ForegroundColor Black}
}
""
write-host "---===ПРОВЕРКА НАСТРОЕК БРАУЗЕРА===---" -BackgroundColor White -ForegroundColor black
if ($IEProxy -eq "1") {Write-Host -BackgroundColor Green -ForegroundColor Black "Прокси-сервер в IE отключен"}
if ($IEProxy -eq "3") {Write-Host -BackgroundColor Red -ForegroundColor Black "Прокси-сервер в IE включен"}
if ($IEProxy -eq "5" -or $IEProxy -eq "9") {Write-Host -BackgroundColor Yellow -ForegroundColor Black "Автоопределение прокси-сервера в IE включено"}
if ($IEProxy -ne "1" -and $IEProxy -ne "3" -and $IEProxy -ne "5" -and $IEProxy -ne "9") {Write-Host -BackgroundColor Yellow -ForegroundColor Black "Настройки IE определить не удалось :("}
""
write-host "---===ПРОВЕРКА ДОСТУПНОСТИ АС ЭТРАН===---" -BackgroundColor White -ForegroundColor black
if ($etran.Open -eq "True") {Write-Host "АС ЭТРАН" $etrserver "доступна" -BackgroundColor Green -ForegroundColor Black} else {Write-Host "АС ЭТРАН 10.248.35.9 недоступна" -BackgroundColor Red -ForegroundColor Black}
if ($vipnet2 -eq "True" -and $IEProxy -eq "1" -and $etran.Open -ne "True")
    {
    if ($tun1_etran -eq "$etrserver" -or $tun2_etran -eq "$etrserver")
        {
        "Возможные причины:"
        "1. В настройках ПО ViPNet выключены туннели;"
        "2. Туннели настроены на работы по виртуальным адресам, доступ нужно проверить вручную;"
        "3. Доступ блокируется на координаторе;"
        "4. Сломался ЭТРАН."
        }
    }
