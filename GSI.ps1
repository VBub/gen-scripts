#This script builds up a bulk of status information and summeries it
#This can be then emailed to anyone who needs this information
#It is mainly to check for possible issues and deal with them before they become a problem
#the top section of the script is for setup

#General Configuration
$networkname = "somedomain.com" #this is used for the email header 
$reportrecipient = "someone@somedomain.com"
$sender = "system@domain.com"
$smtpserver = "mail.domain.com"

#Servers to check for the windows backup status
#Windows Server backups to check
$wsb = @(
"server1.domain.com",
"server2.domain.com"
)
#How many days can we go without a good backup before things are not good?
$gbt=-3


#Percentage that the freespace amount appears in light red
$disklowthreshold = 12
#Percentage that the freespace amount appears in dark red
$diskbadlowthreshold = 8


#SSL certificates to check for expiry
 $SSLurls = @(
 "https://secureserver.domain.com"
 )
#what is considered too close to expiry?
$minimumCertAgeDays = 60


#Domains to check for expiry
 $domainurls = @(
 "domain.com",
 "otherdomain.com"
 )
#what is considered too close to expiry?
$minimumDomainAgeDays = 45


#This will serve as the server list we will check disks with
#default example is all domain controllers OU and a Servers OU
$serverlist = (Get-ADComputer -SearchBase 'OU=Domain Controllers,DC=domain,DC=com' -Filter 'ObjectClass -eq "Computer"')
$serverlist += (Get-ADComputer -SearchBase 'OU=Servers,DC=domain,DC=com' -Filter 'ObjectClass -eq "Computer"')


#Users to check inactivity with
#default example is a Users OU
$userlist = (Get-ADUser -Filter "*" -SearchBase "CN=Users,DC=domain,DC=com" -Properties lastLogon, mail)
#How many days is considered inactive for a user?
$userinactive = 90




#We are sending a HTML based email, this is the header and footer used later
$head = @"
<html><head>
<style>
.maintable {padding:2px;text-align:left;}
.maintable_th {background-color:#f0f0f0}
.maintable_e {background-color:#f8f8f8}
.maintable_o {background-color:#f2f2f2}
.maintable_tdr{text-align:right;}
.maintable_tdrr{text-align:right; background-color:#ffaaaa;}
.maintable_tdrrr{text-align:right; background-color:#ff2222;}

.maintable_tdg{text-align:right; background-color:#aaffaa;}
.maintable_tdb{text-align:right; background-color:#aaaaff;}

</style></head><body>
<p>
"@
$head = $($head + "<p><h1>General Network Status for " + $networkname + "</h1></p>")
$foot = "</body></html>"






#This section will get the Basic Volume information, mainly how much space is free
$ldisks ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Server</th><th>Volume</th><th>Name</th><th>Size</th><th>Used</th><th>FreeSpace</th></tr>"
$eo=0
$lbad=0
$lbadm=0
Write-Host -ForegroundColor DarkMagenta "Logical Volume Information"
$serverlist | ForEach-Object {
    Write-Host -ForegroundColor cyan $("Reading: " + $_.dnshostname)
    
    $sn = $_.Name

    Try{
        $wmifail = $false
        $wmio = (Get-WmiObject -ErrorAction Stop -Query "SELECT * from Win32_LogicalDisk WHERE DriveType = '3'" -Namespace "root\CIMV2" -ComputerName $_.DNSHostName)
    }
    Catch{
        $wmifail = $true
    }

    if($wmifail -eq $true){
        $ldisks =$($ldisks + "<tr><td>" + $sn + "</td><td colspan=5>Error while querying Server</td></tr>")
    }else{
        $wmio | ForEach-Object {
            
            if($eo -eq 0){
                $eo = 1
                $ldisks = $($ldisks + "<tr class=`"maintable_e`">")
            }else{
                $eo = 0
                $ldisks = $($ldisks + "<tr class=`"maintable_o`">")
            }

            $ldisks = $($ldisks + "<td>" + $sn + "</td>")
            $ldisks = $($ldisks + "<td>" + $_.DeviceID + "</td>")
            $ldisks = $($ldisks + "<td>" + $_.VolumeName + "</td>")
            $ldisks = $($ldisks + "<td class=`"maintable_tdr`">" + [math]::Round($_.size / 1GB) + " GiB</td>")
            $ldisks = $($ldisks + "<td class=`"maintable_tdr`">" + [math]::Round(($_.Size - $_.FreeSpace) / 1GB) + " GiB</td>")

            #Work out the free space percentage 
            $fs = [math]::round((100 / $_.Size ) * $_.freespace)

            if($fs -le $disklowthreshold){
                if($fs -le $diskbadlowthreshold){
                    $ldisks = $($ldisks + "<td class=`"maintable_tdrrr`">" + $fs + "%</td></tr>")
                    $lbadm++
                }else{
                    $ldisks = $($ldisks + "<td class=`"maintable_tdrr`">" + $fs + "%</td></tr>")
                    $lbad++
                }
            }else{
                $ldisks = $($ldisks + "<td class=`"maintable_tdr`">" + $fs + "%</td></tr>")
            }
        }
    }
}
$ldisks =$($ldisks + "</table>")






#This section gets the Physical disk information
$pdisks ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Server</th><th>Disk ID</th><th>Disk Name</th><th>Status</th><th>Details</th></tr>"
$eo=0
$pbad=0
Write-Host -ForegroundColor DarkMagenta "Physical Disk Information"
$serverlist | ForEach-Object {
    Write-Host -ForegroundColor cyan $("Reading: " + $_.dnshostname)
    
    $sn = $_.Name

    Try{
        $wmifail = $false
        $wmio = (Get-WmiObject -ErrorAction Stop -Query "SELECT * from Win32_DiskDrive" -Namespace "root\CIMV2" -ComputerName $_.DNSHostName)
    }
    Catch{
        $wmifail = $true
    }

    if($wmifail -eq $true){
        $pdisks =$($pdisks + "<tr><td>" + $sn + "</td><td colspan=4>Error while querying Server</td></tr>")
    }else{
        ForEach ($drive in $wmio) {
            if($eo -eq 0){
                $eo = 1
                $pdisks = $($pdisks + "<tr class=`"maintable_e`">")
            }else{
                $eo = 0
                $pdisks = $($pdisks + "<tr class=`"maintable_o`">")
            }

            $pdisks = $($pdisks + "<td>" + $sn + "</td>")
            $pdisks = $($pdisks + "<td>" + $drive.Index + "</td>")
            $pdisks = $($pdisks + "<td>" + $drive.Model + "</td>")

            #Get the drive status and if it's ok or not
            $fs = $drive.Status 

            if($fs -eq "OK"){
                $pdisks = $($pdisks + "<td class=`"maintable_tdr`">OK</td><td></td></tr>")
            }else{
                $pdisks = $($pdisks + "<td class=`"maintable_tdrrr`">" + $fs + "</td><td>" + $drive.StatusInfo + "</td></tr>")
                $pbad++
            }
        }
    }
}
$pdisks =$($pdisks + "</table>")



#Get windows server backup activity
$lwsbh1 ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Server</th><th>Last Good Backup</th><th>Next Backup</th><th>Copies</th></tr>"
$lwsbh2 ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Server</th><th>Start</th><th>End</th><th>State</th></tr>"
$wsbad =0
$wsvbad =0
$eo=0
Write-Host -ForegroundColor DarkMagenta "Windows Server Backup Activity"
$lwsb=""
foreach ($wsbserver in $wsb){
    Write-Host -ForegroundColor Cyan $("Reading: " + $wsbserver)
    $session = New-PSSession $wsbserver
    $wsbjobs = Invoke-Command -Session $session -ScriptBlock {Get-WBJob -Previous 7}
    $wsbsum = Invoke-Command -Session $session -ScriptBlock {Get-WBSummary}

    $eo=0
    $lwsb = $($lwsb + $lwsbh1)
    if($eo -eq 0){
        $eo = 1
        $lwsb = $($lwsb + "<tr class=`"maintable_e`">")
    }else{
        $eo = 0
        $lwsb = $($lwsb + "<tr class=`"maintable_o`">")
    }


    $lwsb = $($lwsb + "<td>" + $wsbsum.PSComputerName + "</td>")
    if ((Get-Date($wsbsum.LastSuccessfulBackupTime))  -lt (Get-Date([DateTime]::Now).AddDays($gbt))) {
        $lwsb = $($lwsb + "<td class=`"maintable_tdrrr`">" + (get-date $wsbsum.LastSuccessfulBackupTime).ToString("yyyy-MM-dd hh:mm:ss") + "</td>")
        Write-Host -ForegroundColor Cyan $("No Recent good enough backup")
        $wsvbad++
    }else{
        $lwsb = $($lwsb + "<td  class=`"maintable_tdg`">" + (get-date $wsbsum.LastSuccessfulBackupTime).ToString("yyyy-MM-dd hh:mm:ss") + "</td>")
        Write-Host -ForegroundColor Cyan $("Good Recent Backup")
    }
    
    $lwsb = $($lwsb + "<td>" + (get-date $wsbsum.NextBackupTime).ToString("yyyy-MM-dd hh:mm:ss") + "</td>")
    $lwsb = $($lwsb + "<td>" + $wsbsum.NumberOfVersions + "</td></tr>")

    $lwsb = $($lwsb + "</table>")


    $eo=0
    $lwsb = $($lwsb + $lwsbh2)

    foreach($wsbjob in $wsbjobs){
        
        if($eo -eq 0){
            $eo = 1
            $lwsb = $($lwsb + "<tr class=`"maintable_e`">")
        }else{
            $eo = 0
            $lwsb = $($lwsb + "<tr class=`"maintable_o`">")
        }

        #(get-date $Date).ToString("yyyy-MM-dd hh:mm:ss")

        $lwsb =$($lwsb + "<td>" + $wsbjob.PSComputerName + "</td>")
        $lwsb =$($lwsb + "<td>" + (Get-Date $wsbjob.StartTime).ToString("yyyy-MM-dd hh:mm:ss") + "</td>")
        $lwsb =$($lwsb + "<td>" + (get-date $wsbjob.EndTime).ToString("yyyy-MM-dd hh:mm:ss") + "</td>")

        if($wsbjob.HResult -eq 0){
            $lwsb =$($lwsb + "<td>Success</td></tr>")
        }else{
            $lwsb =$($lwsb + "<td class=`"maintable_tdrrr`">Failed</td>")
            $wsbad++
        }
    
    }
    $lwsb = $($lwsb + "</table>")
    Remove-PSSession $session
}


#Get User Activity
$lusers ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>User</th><th>Email</th><th>Last Login</th></tr>"
$eo=0
$ubad=0
$inactd = (get-date).AddDays(-$userinactive)
Write-Host -ForegroundColor DarkMagenta "User Activity"
foreach ($user in $userlist){
    
    if($user.Enabled -eq $True){
    Write-Host -ForegroundColor Cyan $("Reading: " + $user.Name)
        if($eo -eq 0){
            $eo = 1
            $lusers = $($lusers + "<tr class=`"maintable_e`">")
        }else{
            $eo = 0
            $lusers = $($lusers + "<tr class=`"maintable_o`">")
        }

        $inact = 0
        $lngexpires = $user.lastLogon
        if (-not ($lngexpires)) {$lngexpires = 0 }

        If (($lngexpires -eq 0) -or ($lngexpires -gt [DateTime]::MaxValue.Ticks)){
            $LastLogon = "Never"
        }Else{
            $Date = [DateTime]$lngexpires
            $Date = [DateTime]$Date.AddYears(1600)
            $LastLogon = (get-date $Date).ToString("yyyy-MM-dd hh:mm:ss")

            if([datetime]$Date -lt [datetime]$inactd){
                $inact = 1
            }else{
                $inact = 0
            }
         }
         $lusers = $($lusers + "<td>" + $user.Name + "</td><td>" + $user.mail + "</td>")
         if($inact -eq 1){
            $lusers = $($lusers + "<td class=`"maintable_tdb`">" + $LastLogon + "</td></tr>")
            $ubad++
         }else{
            $lusers = $($lusers + "<td class=`"maintable_tdr`">" + $LastLogon + "</td></tr>")
         }
    }
}
$lusers = $($lusers + "</table>")








#SSL cert checks
$lssl ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Addreess</th><th>Name</th><th>Issuer</th><th>Days Left</th></tr>"
$eo=0
$sbad=0
$timeoutMilliseconds = 10000
Write-Host -ForegroundColor DarkMagenta "SSL Checks"
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
foreach ($url in $SSLurls){
    Write-Host $("Checking " + $url) -ForegroundColor Cyan
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Timeout = $timeoutMilliseconds
    $ssler=0
    try {$req.GetResponse() |Out-Null} 
    catch {
    Write-Host Exception while checking URL $url`: $_ -f Red 
    $ssler=1
    }


    $expiration = $req.ServicePoint.Certificate.GetExpirationDateString()
    $expiration = [datetime](Get-Date $expiration).ToLocalTime()
    [int]$certExpiresIn = ($expiration - $(get-date)).Days
    $certName = $req.ServicePoint.Certificate.GetName()
    $certIssuer = $req.ServicePoint.Certificate.GetIssuerName()
    if($eo -eq 0){
        $eo = 1
        $lssl = $($lssl + "<tr class=`"maintable_e`">")
    }else{
        $eo = 0
        $lssl = $($lssl + "<tr class=`"maintable_o`">")
    }

    if($ssler -eq 1){
        $lssl = $($lssl + "<td>" + $url + "</td><td colspan=3>Error while checking URL</td>")
    }else{
        $lssl = $($lssl + "<td>" + $url + "</td><td>" + $certName + "</td><td>" + $certIssuer + "</td>")
        if ($certExpiresIn -gt $minimumCertAgeDays){
            $lssl = $($lssl + "<td class=`"maintable_tdg`">" + $certExpiresIn + "</td></tr>")
        }else{
            $lssl = $($lssl + "<td class=`"maintable_tdrrr`">" + $certExpiresIn + "</td></tr>")
            $sbad++
        }
    }

    rv req
    rv expiration
    rv certExpiresIn
}
$lssl = $($lssl + "</table>")







#Domain Expiry Checks
$ddomain ="<table class=`"maintable`"><tr class=`"maintable_th`"><th>Domain Name</th><th>Expires On</th><th>Registrar</th></tr>"
$eo=0
$dbad=0
Write-Host -ForegroundColor DarkMagenta "Domain Checks"
foreach ($Domain in $domainurls){
    

    Write-Host $("Checking " + $Domain) -ForegroundColor Cyan
    $web = New-WebServiceProxy ‘http://www.webservicex.net/whois.asmx?WSDL’
    $result = $web.GetWhoIs($Domain)

    $result = $result.Split("`r`n")
    foreach ($r in $result ) {
        $ligne = $r.split(":")
        if ( $ligne[0].Trim() -eq "Expiration Date" ){
            $expirationdate = $ligne[1].trim()
        }
        if ( $ligne[0].Trim() -eq "Expiry date" ){
            $expirationdate = $ligne[1].trim()
        }
        if ( $ligne[0].Trim() -eq "Registry Expiry Date" ){

            $expirationdate = $ligne[1].split("T")[0].trim()
        }        
        if ( $ligne[0].Trim() -eq "Registrar" ){

            $registrar = $ligne[1].split("T")[0].trim()
        }        
        if ( $ligne[0].Trim() -eq "Sponsoring Registrar" ){

            $registrar = $ligne[1].split("T")[0].trim()
        }       
    }

    if($eo -eq 0){
        $eo = 1
        $ddomain = $($ddomain + "<tr class=`"maintable_e`">")
    }else{
        $eo = 0
        $ddomain = $($ddomain + "<tr class=`"maintable_o`">")
    }

    $d = (Get-Date -Date $expirationdate).AddDays(-$minimumDomainAgeDays)
    if ($d -gt (Get-Date)){
        $ddomain = $($ddomain + "<td>" + $Domain + "</td><td class=`"maintable_tdr`">" + $expirationdate + "</td><td>" + $registrar + "</td></tr>")
    }else{
        $ddomain = $($ddomain + "<td>" + $Domain + "</td><td class=`"maintable_tdrrr`">" + $expirationdate + "</td><td>" + $registrar + "</td></tr>")
        $dbad++
    }
}
$ddomain = $($ddomain + "</table>")













#Summerize the basics at the top of the email
$sumt = "<table class=`"maintable`"><tr class=`"maintable_th`"><th>Section</th><th>Issues</th></tr>"
if($lbad -eq 0 -and $lbadm -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Logical Volumes</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    if($lbadm -gt 0){
        $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Logical Volumes</td><td class=`"maintable_tdrrr`">" + $lbad + " Minor Issues<br>" + $lbadm + " Major Issues</td></tr>")
    }else{
        $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Logical Volumes</td><td class=`"maintable_tdrr`">" + $lbad + " Minor Issues</td></tr>")
    }
}
if($pbad -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Physical Disks</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Physical Disks</td><td class=`"maintable_tdrr`">" + $pbad + " Issues</td></tr>")
}

if($wsvbad -eq 0 -and $wsbad -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Windows Server Backup</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    if($wsvbad -gt 0){
        $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Windows Server Backups</td><td class=`"maintable_tdrrr`">" + $wsbad + " Minor Issues<br>" + $wsvbad + " Major Issues</td></tr>")
    }else{
        $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Windows Server Backups</td><td class=`"maintable_tdrr`">" + $wsbad + " Minor Issues</td></tr>")
    }
}

if($dbad -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Domain Checks</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Domain Checks</td><td class=`"maintable_tdrrr`">" + $dbad + " Issues</td></tr>")
}
if($sbad -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>SSL Certs</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>SSL Certs</td><td class=`"maintable_tdrr`">" + $sbad + " Issues</td></tr>")
}
if($ubad -eq 0){
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Users</td><td class=`"maintable_tdg`">No Detected Issues</td></tr>")
}else{
    $sumt =$($sumt + "<tr class=`"maintable_e`"><td>Users</td><td class=`"maintable_tdb`">" + $ubad + " Users are Inactive</td></tr>")
}

$sumt += "</table>"

#Now assemble all the constructed data into an email
$htmlmessage = $head
$htmlmessage = $($htmlmessage + "<p><h2>Status Summary</h2></p>" + $sumt)
$htmlmessage = $($htmlmessage + "<p><h2>Server Logical Volume Information</h2></p>" + $ldisks)
$htmlmessage = $($htmlmessage + "<p><h2>Server Physical Disk Information</h2></p>" + $pdisks)
$htmlmessage = $($htmlmessage + "<p><h2>Windows Server Backup Information</h2></p>" + $lwsb)
$htmlmessage = $($htmlmessage + "<p><h2>Domain Checks</h2></p>" + $ddomain)
$htmlmessage = $($htmlmessage + "<p><h2>SSL Certificate Checks</h2></p>" + $lssl)
$htmlmessage = $($htmlmessage + "<p><h2>User Information</h2></p>" + $lusers)
$htmlmessage = $($htmlmessage + $foot)



#Finally the email subject
$subject = $("Network Status " + $networkname + " " + (Get-Date -Format "F"))

#Send the email out
Write-Host -ForegroundColor DarkCyan $("Sending Email: " + $subject)
Send-MailMessage -Subject $subject -BodyAsHtml $htmlmessage -To $reportrecipient -From $sender -SmtpServer $smtpserver  -UseSsl

