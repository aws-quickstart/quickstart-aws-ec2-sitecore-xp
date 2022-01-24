[CmdletBinding()]
param (
    [string]$SCQSPrefix,
    [string]$QSS3BucketName,
    [string]$QSS3KeyPrefix,
    [string]$QSS3BucketRegion
)

$S3BucketName = (Get-SSMParameter -Name "/$SCQSPrefix/user/s3bucket/name").Value # The bucket containing the Sitecore 9.3 install files and sitecore license.zip file
$S3ScResourcesPrefix = (Get-SSMParameter -Name "/$SCQSPrefix/user/s3bucket/scresourcesprefix").Value # The prefix where the install files are located. eg: sitecorefiles\
$localPath = (Get-SSMParameter -Name "/$SCQSPrefix/user/localresourcespath").Value # Path on the instance where the files will be located
$localLogPath = "$localPath\logs" # Path on the instance where the log files will be located
$qslocalPath = (Get-SSMParameter -Name "/$SCQSPrefix/user/localqsresourcespath").Value # Path on the instance where the Quick Start files will be located

# CloudWatch values
$logGroupName = "$SCQSPrefix-ssm-bootstrap"
$logStreamName = "BaseImage-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
# Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $logStreamName -LogString $LogString

# Check and create logs path
If(!(test-path $localLogPath))
{
      New-Item -ItemType Directory -Force -Path $localLogPath
}

#Modify Registry disable IE enhanced security
$path = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\"
New-ItemProperty -Name 'IsInstalled' -path $path -Value '0' -PropertyType DWORD -Force
New-ItemProperty -Name "IsInstalled" -path "$path{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Value "00000000" -PropertyType DWORD -Force
New-ItemProperty -Name "IsInstalled" -path "$path{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Value "00000000" -PropertyType DWORD -Force
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $logStreamName -LogString 'Disabled IE Enhanced Security'
# Disable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $logStreamName -LogString 'Disabled Windows Firewall'

# Get Sitecore install read-s3 files from S3
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $logStreamName -LogString 'Initiating Sitecore resource files download'
$bucket_locationConstraint = Get-S3BucketLocation -BucketName $s3BucketName
$BucketRegionValue = $bucket_locationConstraint.value

if (!$BucketRegionValue) {
        $bucketRegion = 'us-east-1'
    }
elseif ($BucketRegionValue -eq 'EU') {
        $bucketRegion = 'eu-west-1'
    }
else {
        $bucketRegion =  $BucketRegionValue
    }

$files = Get-S3Object -BucketName $s3BucketName -Region $bucketRegion | Where-Object { ($_.Key -like "$S3ScResourcesPrefix*.zip") }
foreach ($file in $files) {
    $filename = Split-path -Path $file.key -leaf
    Read-S3Object -BucketName $s3BucketName -Key $file.key -File "$localpath\$filename" -Region $bucketRegion
    if ($? -eq 'true') { Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Downloaded $filename" }
    if (($file.key -like '*configuration*')) {
        Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString (Expand-Archive -LiteralPath "$localpath\$filename" -DestinationPath $localpath -Force -Verbose *>&1 | Out-String)
    }
}

# Change SSL Flag in json files this disables SNI in IIS
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $logStreamName -LogString 'Changing SSL Flag in JSON files'
$files = Get-ChildItem -Path $localpath -Recurse -ErrorAction SilentlyContinue -Filter *.json | Where-Object { ($_.Name -like 'IdentityServer*') -or ($_.Name -like 'sitecore-xp1*') -or ($_.Name -like 'xconnect-xp1*') }
foreach ($file in $files) {
    ((Get-Content -Path "$localpath\$file" -Raw) -replace '"SSLFlags": 1,', '"SSLFlags": 0,') | Set-Content -Path "$localpath\$file"
    Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Updated SSL flag to 0 for config file : $localpath\$file"
}


# Install NuGet provider
Install-PackageProvider -Name NuGet -Force
if ($? -eq 'true') {
    Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Successfully installed NuGet Package Privider'
    }
else {
    Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Failed to install NuGet Package Privider'
    }

# Register Sitecore repository
Register-PSRepository -Name SitecoreGallery -SourceLocation https://sitecore.myget.org/F/sc-powershell/api/v2 -InstallationPolicy Trusted  | Out-Null
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Registered Repository SiteCoreGallery'
# Install IIS Management Scripting Tools
Get-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools -Verbose *>&1 | Tee-Object -FilePath "$localLogPath\iismgmttoolsinstall.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\iismgmttoolsinstall.log" -raw)
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed IIS Management Scripting Tools'
# Install Web Management Console
Install-WindowsFeature -Name web-mgmt-console -Confirm:$false -Verbose *>&1 | Tee-Object -FilePath "$localLogPath\webmgmtconsole.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\webmgmtconsole.log" -raw)
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed Web Management Console'
# Install SQL Server Module
Install-Module SQLServer -Force -Verbose *>&1 | Tee-Object -FilePath "$localLogPath\sqlmodule.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\sqlmodule.log" -raw)
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed SQL Server Module'
# Modified registry key that will assist with the error about trying to edit a deleted registry entry
New-ItemProperty -Name DisableForceUnload -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Value "1" -PropertyType DWORD -Force
#Install SiteCore Install Framework
Install-Module SitecoreInstallFramework -Force -Verbose *>&1 | Tee-Object -FilePath "$localLogPath\SIFinstall.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\SIFinstall.log" -raw)
#Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString (Install-Module SitecoreInstallFramework -Force -Verbose *>&1 | Out-String)
#Install-Module SitecoreInstallFramework -Force
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed Module SitecoreInstallFramework'
# Install Sitecore configuration
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Initiating installation of Sitecore Prerequisites'
Install-SitecoreConfiguration -Path "$localPath\Prerequisites.json" -Verbose *>&1 | Tee-Object -FilePath "$localLogPath\Prerequisites.log"
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\Prerequisites.log" -raw)
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString 'Installed Sitecore Configuration'
Write-SSMParameter -Name "/$SCQSPrefix/instance/image/custom" -Type "String" -Value (Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/instance-id) -Overwrite:$true
Write-AWSQuickStartCWLogsEntry -logGroupName $logGroupName -LogStreamName $LogStreamName -LogString "Added instance ID to parameter store parameter /$SCQSPrefix/instance/image/custom"