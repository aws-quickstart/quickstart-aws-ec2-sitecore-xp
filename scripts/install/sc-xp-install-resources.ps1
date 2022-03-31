[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet(
        'DbResources',
        'IdentityServer',
        'Collection',
        'CollectionSearch',
        'ReferenceData',
        'MarketingAutomation',
        'MarketingAutomationReporting',
        'CortexProcessing',
        'CortexReporting',
        'CM',
        'CD',
        'Prc',
        'Rep'
    )]
    [string]
    $Role,
    [Parameter(Mandatory)]
    $SCQSPrefix,
    [Parameter(Mandatory)]
    $Region,
    $StackName
)
If (![Environment]::Is64BitProcess) {
    Write-Host "Please run 64-bit PowerShell" -foregroundcolor "yellow"
    return
}
Import-Module SitecoreInstallFramework

$DNSSuffix = (Get-SSMParameter -Name "/$SCQSPrefix/service/internaldns").Value

# region Role Mapping
$roleMapping = @{
    'IdentityServer'               = "identity"
    'Collection'                   = "coll"
    'CollectionSearch'             = "collsearch"
    'ReferenceData'                = "refdata"
    'MarketingAutomation'          = "mktauto"
    'MarketingAutomationReporting' = "mktautorep"
    'CortexProcessing'             = "cortexproc"
    'CortexReporting'              = "cortexrep"
    'CM'                           = "contentmgmt"
    'CD'                           = "contentdel"
    'Prc'                          = "proc"
    'Rep'                          = "rep"
}
# endregion

# region Parameter Values
$parameters = @{
    SCPrefix                      = (Get-SSMParameter -Name "/$SCQSPrefix/user/sitecoreprefix").Value
    SCInstallRoot                 = (Get-SSMParameter -Name "/$SCQSPrefix/user/localresourcespath").Value
    PasswordRecoveryUrl           = (Get-SSMParameter -Name "/$SCQSPrefix/service/passwordrecoveryurl").Value
    allowedCorsOrigins            = (Get-SSMParameter -Name "/$SCQSPrefix/service/allowedCorsOrigins").Value
    Environment                   = (Get-SSMParameter -Name "/$SCQSPrefix/user/environment").Value
    LogLevel                      = (Get-SSMParameter -Name "/$SCQSPrefix/user/logLevel").Value
    SolrCorePrefix                = (Get-SSMParameter -Name "/$SCQSPrefix/user/solrcoreprefix").Value
    SolrUrl                       = (Get-SSMParameter -Name "/$SCQSPrefix/user/solruri").Value
    InstanceCertificateThumbPrint = (Get-SSMParameter -Name "/$SCQSPrefix/cert/instance/thumbprint").Value
    xConnectCertificateThumbPrint = (Get-SSMParameter -Name "/$SCQSPrefix/cert/xconnect/thumbprint").Value
    SQLServer                     = (Get-SSMParameter -Name "/$SCQSPrefix/sql/server").Value
}
# endregion

$DNSNames = @{
    IdentityServerDNS               = (Get-SSMParameter -Name "/$SCQSPrefix/service/isdns").Value #$roleMapping.IdentityServer + '.' + $DNSSuffix
    CMDNS                           = (Get-SSMParameter -Name "/$SCQSPrefix/service/cmdns").Value 
    CDDNS                           = (Get-SSMParameter -Name "/$SCQSPrefix/service/cddns").Value 
    PrcDNS                          = $roleMapping.Prc + '.' + $DNSSuffix
    RepDNS                          = $roleMapping.Rep + '.' + $DNSSuffix
    CollectionDNS                   = $roleMapping.Collection + '.' + $DNSSuffix
    CollectionSearchDNS             = $roleMapping.CollectionSearch + '.' + $DNSSuffix
    MarketingAutomationDNS          = $roleMapping.MarketingAutomation + '.' + $DNSSuffix
    MarketingAutomationReportingDNS = $roleMapping.MarketingAutomationReporting + '.' + $DNSSuffix
    ReferenceDataDNS                = $roleMapping.ReferenceData + '.' + $DNSSuffix
    CortexProcessingDNS             = $roleMapping.CortexProcessing + '.' + $DNSSuffix
    CortexReportingDNS              = $roleMapping.CortexReporting + '.' + $DNSSuffix
}

$ServiceURLs = @{
    PasswordRecoveryUrl                  = (Get-SSMParameter -Name "/$SCQSPrefix/service/passwordrecoveryurl").Value  # https:// (Host name of CM instance) "https://" + $DNSNames.CMDNS
    XConnectCollectionService            = "https://" + $DNSNames.CollectionDNS                     # https://XConnectCollection
    XConnectSearchService                = "https://" + $DNSNames.CollectionSearchDNS               # https://XConnectSearch : The xConnect Search Indexer is bundled with the xConnect Collection Search
    XConnectCollectionSearchService      = "https://" + $DNSNames.CollectionSearchDNS               # https://XConnectCollectionSearch
    XConnectReferenceDataService         = "https://" + $DNSNames.ReferenceDataDNS                  # https://XConnectReferenceData
    SitecoreIdentityAuthority            = "https://" + $DNSNames.IdentityServerDNS                 # https://SitecoreIdentityServerHost
    MarketingAutomationOperationsService = "https://" + $DNSNames.MarketingAutomationDNS            # https://XConnectMarketingAutomation
    MarketingAutomationReportingService  = "https://" + $DNSNames.MarketingAutomationReportingDNS   # https://XConnectMarketingAutomationReporting
    CortexReportingService               = "https://" + $DNSNames.CortexReportingDNS                # https://CortexReporting
    ProcessingService                    = "https://" + $DNSNames.PrcDNS                            # https://SitecoreProcessing
    ReportingService                     = "https://" + $DNSNames.RepDNS                            # https://SitecoreReporting
}

# region Secrets Manager Values
$secrets = @{
    SitecoreIdentitySecret         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sitecoreidentitysecret").SecretString).secret
    SitecoreAdminPassword          = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sitecoreadmin").SecretString).password
    ReportingServiceApiKey         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-reportingserviceapikey").SecretString).apikey
    ClientSecret                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-clientsecret").SecretString).secret
    SqlAdminUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqladmin").SecretString).username
    SqlAdminPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqladmin").SecretString).password
    SqlSecurityUser                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlsecurity").SecretString).username
    SqlSecurityPassword            = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlsecurity").SecretString).password
    SqlCollectionUser              = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcollection").SecretString).username
    SqlCollectionPassword          = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcollection").SecretString).password
    SqlMessagingUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmessaging").SecretString).username
    SqlMessagingPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmessaging").SecretString).password
    SqlProcessingEngineUser        = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingengine").SecretString).username
    SqlProcessingEnginePassword    = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingengine").SecretString).password
    SqlReportingUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlreporting").SecretString).username
    SqlReportingPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlreporting").SecretString).password
    SqlCoreUser                    = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcore").SecretString).username
    SqlCorePassword                = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlcore").SecretString).password
    SqlMainUser                  = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmain").SecretString).username
    SqlMainPassword              = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmain").SecretString).password
    SqlWebUser                     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlweb").SecretString).username
    SqlWebPassword                 = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlweb").SecretString).password
    SqlReferenceDataUser           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlreferencedata").SecretString).username
    SqlReferenceDataPassword       = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlreferencedata").SecretString).password
    SqlFormsUser                   = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlforms").SecretString).username
    SqlFormsPassword               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlforms").SecretString).password
    SqlExmMainUser               = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlexmmain").SecretString).username
    SqlExmMainPassword           = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlexmmain").SecretString).password
    SqlProcessingPoolsUser         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingpools").SecretString).username
    SqlProcessingPoolsPassword     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingpools").SecretString).password
    SqlMarketingAutomationUser     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmarketingautomation").SecretString).username
    SqlMarketingAutomationPassword = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlmarketingautomation").SecretString).password
    SqlProcessingTasksUser         = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingtasks").SecretString).username
    SqlProcessingTasksPassword     = (ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId "sitecore-quickstart-$SCQSPrefix-sqlprocessingtasks").SecretString).password
}

# Endregion

# Region local values
$local = @{
    ComputerName            = $(Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/hostname)
    SiteName                = "$($parameters.SCPrefix).$Role"
    Package                 = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.scwdp.zip").FullName
    jsonPath                = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$Role.json").FullName
    # jsonPathCustom          = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)/aws-custom" -Filter "*$Role.json").FullName
    CustomConfigurationFile = "$Role.json"
    LicenseFile             = "$($parameters.SCInstallRoot)\license.xml"
    SkipDBInstallOnRoles    = $true
}
# Endregion

# CW Logging
$localLogPath = "$($parameters.SCInstallRoot)\logs" # Path on the instance where the log files will be located
$LogGroupName = "$SCQSPrefix-$Role"
$LogStreamName = "$Role-RoleInstallation-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )

If (!(test-path $localLogPath)) {
    New-Item -ItemType Directory -Force -Path $localLogPath
}


$skip = @()

switch ($Role) {
    'DbResources' {
        $dbRoles = @(
            'Collection'
            'ReferenceData'
            'CortexProcessing'
            'CortexReporting'
            'CM'
            'Prc'
        )
        foreach ($dbRole in $dbRoles) {
            $local.SiteName = "$($parameters.SCPrefix).$dbRole"
            $local.Package = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.scwdp.zip").FullName
            $local.jsonPath = (Get-ChildItem -LiteralPath "$($parameters.SCInstallRoot)" -Filter "*$DbRole.json").FullName
            $appCmd = "C:\windows\system32\inetsrv\appcmd.exe"
            switch ($dbRole) {
                'Collection' {
                    $DeploymentParameters = @{
                        Package                        = $($local.Package)
                        XConnectCert                   = $($parameters.xConnectCertificateThumbPrint)
                        SiteName                       = $($local.SiteName)
                        SqlDbPrefix                    = $($parameters.SCPrefix)
                        SqlServer                      = $($parameters.SQLServer)
                        SqlAdminUser                   = $($secrets.SqlAdminUser)
                        SqlAdminPassword               = $($secrets.SqlAdminPassword)
                        SqlCollectionUser              = $($secrets.SqlCollectionUser)
                        SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
                        SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
                        SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
                        SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
                        SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
                        SqlMessagingUser               = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        'SetAppPoolCertStorePermissions'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'SupportListManagerLargeUpload'
                        'CreateHostHeader'
                        'SetPermissions'
                        # 'InstallWDP'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'CleanShards'
                        # 'CreateShards'
                        # 'CreateShardApplicationDatabaseServerLoginInvokeSqlCmd'
                        # 'CreateShardManagerApplicationDatabaseUserInvokeSqlCmd'
                        # 'CreateShard0ApplicationDatabaseUserInvokeSqlCmd'
                        # 'CreateShard1ApplicationDatabaseUserInvokeSqlCmd'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'ReferenceData' {
                    $DeploymentParameters = @{
                        Package                  = $($local.Package)
                        LicenseFile              = $($local.LicenseFile)
                        SiteName                 = $($local.SiteName)
                        XConnectCert             = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix              = $($parameters.SCPrefix)
                        SqlServer                = $($parameters.SQLServer)
                        SqlAdminUser             = $($secrets.SqlAdminUser)
                        SqlAdminPassword         = $($secrets.SqlAdminPassword)
                        SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        'SetAppPoolCertStorePermissions'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        # 'InstallWDP'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'CortexProcessing' {
                    $DeploymentParameters = @{
                        Package                     = $($local.Package)
                        LicenseFile                 = $($local.LicenseFile)
                        SiteName                    = $($local.SiteName)
                        SSLCert                     = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert                = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix                 = $($parameters.SCPrefix)
                        SqlServer                   = $($parameters.SQLServer)
                        SqlAdminUser                = $($secrets.SqlAdminUser)
                        SqlAdminPassword            = $($secrets.SqlAdminPassword)
                        SqlMessagingUser            = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword        = $($secrets.SqlMessagingPassword)
                        SqlProcessingEngineUser     = $($secrets.SqlProcessingEngineUser)
                        SqlProcessingEnginePassword = $($secrets.SqlProcessingEnginePassword)
                        SqlReportingUser            = $($secrets.SqlReportingUser)
                        SqlReportingPassword        = $($secrets.SqlReportingPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        'SetAppPoolCertStorePermissions'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        # 'StopService'
                        # 'RemoveService'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        # 'InstallWDP'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                        'SetServicesCertStorePermissions'
                        'CreateServiceLogPath'
                        'SetProcessingEngineServiceLicense'
                        'SetServicePermissions'
                        'InstallService'
                        'StartService'
                    )
                }
                'CortexReporting' {
                    $DeploymentParameters = @{
                        Package              = $($local.Package)
                        LicenseFile          = $($local.LicenseFile)
                        SiteName             = $($local.SiteName)
                        SSLCert              = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert         = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix          = $($parameters.SCPrefix)
                        SqlServer            = $($parameters.SQLServer)
                        SqlAdminUser         = $($secrets.SqlAdminUser)
                        SqlAdminPassword     = $($secrets.SqlAdminPassword)
                        SqlReportingUser     = $($secrets.SqlReportingUser)
                        SqlReportingPassword = $($secrets.SqlReportingPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        'SetAppPoolCertStorePermissions'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'SetClientCertificatePermissions'
                        'CreateHostHeader'
                        'SetPermissions'
                        # 'InstallWDP'
                        'SetLicense'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                'CM' {
                    $DeploymentParameters = @{
                        Package                  = $($local.Package)
                        LicenseFile              = $($local.LicenseFile)
                        SiteName                 = $($local.SiteName)
                        SSLCert                  = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert             = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix              = $($parameters.SCPrefix)
                        SqlServer                = $($parameters.SQLServer)
                        SitecoreAdminPassword    = $($secrets.SitecoreAdminPassword)
                        SqlAdminUser             = $($secrets.SqlAdminUser)
                        SqlAdminPassword         = $($secrets.SqlAdminPassword)
                        SqlCoreUser              = $($secrets.SqlCoreUser)
                        SqlCorePassword          = $($secrets.SqlCorePassword)
                        SqlSecurityUser          = $($secrets.SqlSecurityUser)
                        SqlSecurityPassword      = $($secrets.SqlSecurityPassword)
                        SqlMasterUser            = $($secrets.SqlMainUser)
                        SqlMasterPassword        = $($secrets.SqlMainPassword)
                        SqlWebUser               = $($secrets.SqlWebUser)
                        SqlWebPassword           = $($secrets.SqlWebPassword)
                        SqlReportingUser         = $($secrets.SqlReportingUser)
                        SqlReportingPassword     = $($secrets.SqlReportingPassword)
                        SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
                        SqlFormsUser             = $($secrets.SqlFormsUser)
                        SqlFormsPassword         = $($secrets.SqlFormsPassword)
                        SqlExmMasterUser         = $($secrets.SqlExmMainUser)
                        SqlExmMasterPassword     = $($secrets.SqlExmMainPassword)
                        SqlMessagingUser         = $($secrets.SqlMessagingUser)
                        SqlMessagingPassword     = $($secrets.SqlMessagingPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetCertStorePermissions'
                        # 'InstallWDP'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'SetLicense'
                        'StartAppPool'
                        'StartWebsite'
                        'UpdateSolrSchema'
                        # 'DisplayPassword'
                    )
                }
                'Prc' {
                    $DeploymentParameters = @{
                        Package                    = $($local.Package)
                        LicenseFile                = $($local.LicenseFile)
                        SiteName                   = $($local.SiteName)
                        SSLCert                    = $($parameters.InstanceCertificateThumbPrint)
                        XConnectCert               = $($parameters.xConnectCertificateThumbPrint)
                        SqlDbPrefix                = $($parameters.SCPrefix)
                        SqlServer                  = $($parameters.SQLServer)
                        SqlAdminUser               = $($secrets.SqlAdminUser)
                        SqlAdminPassword           = $($secrets.SqlAdminPassword)
                        SqlCoreUser                = $($secrets.SqlCoreUser)
                        SqlCorePassword            = $($secrets.SqlCorePassword)
                        SqlSecurityUser            = $($secrets.SqlSecurityUser)
                        SqlSecurityPassword        = $($secrets.SqlSecurityPassword)
                        SqlMasterUser              = $($secrets.SqlMainUser)
                        SqlMasterPassword          = $($secrets.SqlMainPassword)
                        SqlReportingUser           = $($secrets.SqlReportingUser)
                        SqlReportingPassword       = $($secrets.SqlReportingPassword)
                        SqlReferenceDataUser       = $($secrets.SqlReferenceDataUser)
                        SqlReferenceDataPassword   = $($secrets.SqlReferenceDataPassword)
                        SqlProcessingPoolsUser     = $($secrets.SqlProcessingPoolsUser)
                        SqlProcessingPoolsPassword = $($secrets.SqlProcessingPoolsPassword)
                        SqlProcessingTasksUser     = $($secrets.SqlProcessingTasksUser)
                        SqlProcessingTasksPassword = $($secrets.SqlProcessingTasksPassword)
                    }
                    $skip = @(
                        # 'DownloadWDP'
                        # 'CreatePaths'
                        # 'CreateAppPool'
                        # 'CreateWebsite'
                        'StopWebsite'
                        'StopAppPool'
                        'RemoveDefaultBinding'
                        'CreateBindingsWithThumbprint'
                        'CreateHostHeader'
                        'SetPermissions'
                        'SetCertStorePermissions'
                        # 'InstallWDP'
                        'CreateBindingsWithDevelopmentThumbprint'
                        'SetLicense'
                        'StartAppPool'
                        'StartWebsite'
                    )
                }
                Default { }
            }

            Push-Location $($parameters.SCInstallRoot)
            Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPath) -Skip $skip -Verbose *>&1 | Tee-Object "$localLogPath\db-$DbRole.log"
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\db-$DbRole.log" -raw)
            & $appcmd delete site $($local.SiteName)
            & $appcmd delete apppool$($local.SiteName)
            Pop-Location
        }
    }
    'IdentityServer' {
        $DeploymentParameters = @{
            Package                 = $($local.Package)
            SitecoreIdentityCert    = $($parameters.InstanceCertificateThumbPrint)
            LicenseFile             = $($local.LicenseFile)
            SiteName                = $($local.SiteName)
            SqlServer               = $($parameters.SQLServer)
            SqlDbPrefix             = $($parameters.SCPrefix)
            SqlSecurityPassword     = $($secrets.SqlSecurityPassword)
            PasswordRecoveryUrl     = $($ServiceURLs.PasswordRecoveryUrl)
            AllowedCorsOrigins      = $($parameters.allowedCorsOrigins)
            ClientSecret            = $($secrets.ClientSecret)
            CustomConfigurationFile = $($local.CustomConfigurationFile)
            HostMappingName         = $($DNSNames.IdentityServerDNS)
            DnsName                 = $($DNSNames.IdentityServerDNS)
            # SitePhysicalRoot        = ""
            # SqlSecurityDbName       = ""
            SqlSecurityUser         = $($secrets.SqlSecurityUser)
            # PackagesTempLocation    = ""
            # DownloadLocations       = ""
        }
    }
    'CM' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SqlDbPrefix                          = $($parameters.SCPrefix)
            SolrCorePrefix                       = $($parameters.SolrCorePrefix)
            SSLCert                              = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                         = $($parameters.xConnectCertificateThumbPrint)
            SiteName                             = $($local.SiteName)
            # SitePhysicalRoot
            SitecoreAdminPassword                = $($secrets.SitecoreAdminPassword)
            SqlAdminUser                         = $($secrets.SqlAdminUser)
            SqlAdminPassword                     = $($secrets.SqlAdminPassword)
            SqlCoreUser                          = $($secrets.SqlCoreUser)
            SqlCorePassword                      = $($secrets.SqlCorePassword)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlMasterUser                        = $($secrets.SqlMainUser)
            SqlMasterPassword                    = $($secrets.SqlMainPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlReportingUser                     = $($secrets.SqlReportingUser)
            SqlReportingPassword                 = $($secrets.SqlReportingPassword)
            SqlReferenceDataUser                 = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword             = $($secrets.SqlReferenceDataPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            SqlExmMasterUser                     = $($secrets.SqlExmMainUser)
            SqlExmMasterPassword                 = $($secrets.SqlExmMainPassword)
            SqlMessagingUser                     = $($secrets.SqlMessagingUser)
            SqlMessagingPassword                 = $($secrets.SqlMessagingPassword)
            SqlServer                            = $($parameters.SQLServer)
            # ExmEdsProvider
            SolrUrl                              = $($parameters.SolrUrl)
            ProcessingService                    = $($ServiceURLs.ProcessingService)
            ReportingService                     = $($ServiceURLs.ReportingService)
            ReportingServiceApiKey               = $($secrets.ReportingServiceApiKey)
            XConnectCollectionSearchService      = $($ServiceURLs.XConnectCollectionSearchService)
            XConnectReferenceDataService         = $($ServiceURLs.XConnectReferenceDataService)
            MarketingAutomationOperationsService = $($ServiceURLs.MarketingAutomationOperationsService)
            MarketingAutomationReportingService  = $($ServiceURLs.MarketingAutomationReportingService)
            CortexReportingService               = $($ServiceURLs.CortexReportingService)
            # EXMCryptographicKey
            # EXMAuthenticationKey
            SitecoreIdentityAuthority            = $($ServiceURLs.SitecoreIdentityAuthority)
            SitecoreIdentitySecret               = $($secrets.SitecoreIdentitySecret)
            # TelerikEncryptionKey
            HostMappingName                      = $($DNSNames.CMDNS)
            DnsName                              = $($DNSNames.CMDNS)
            SkipDatabaseInstallation             = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
        $skip = @(
            # 'DownloadWDP'
            # 'CreatePaths'
            # 'CreateAppPool'
            # 'CreateWebsite'
            # 'StopWebsite'
            # 'StopAppPool'
            # 'RemoveDefaultBinding' 
            # 'CreateBindingsWithThumbprint'
            # 'CreateHostHeader'
            # 'SetPermissions'
            # 'SetCertStorePermissions'
            # 'InstallWDP'
            # 'CreateBindingsWithDevelopmentThumbprint'
            # 'SetLicense'
            # 'StartAppPool'
            # 'StartWebsite'
            'UpdateSolrSchema'
            'DisplayPassword'
        )
    }
    'CD' {
        $DeploymentParameters = @{
            Package                              = $($local.Package)
            LicenseFile                          = $($local.LicenseFile)
            SqlDbPrefix                          = $($parameters.SCPrefix)
            SolrCorePrefix                       = $($parameters.SolrCorePrefix)
            XConnectCert                         = $($parameters.xConnectCertificateThumbPrint)
            SiteName                             = $($local.SiteName)
            # SitePhysicalRoot
            SolrUrl                              = $($parameters.SolrUrl)
            XConnectCollectionService            = $($ServiceURLs.XConnectCollectionService)
            XConnectReferenceDataService         = $($ServiceURLs.XConnectReferenceDataService)
            MarketingAutomationOperationsService = $($ServiceURLs.MarketingAutomationOperationsService)
            MarketingAutomationReportingService  = $($ServiceURLs.MarketingAutomationReportingService)
            SitecoreIdentityAuthority            = $($ServiceURLs.SitecoreIdentityAuthority)
            SqlServer                            = $($parameters.SQLServer)
            SqlSecurityUser                      = $($secrets.SqlSecurityUser)
            SqlSecurityPassword                  = $($secrets.SqlSecurityPassword)
            SqlWebUser                           = $($secrets.SqlWebUser)
            SqlWebPassword                       = $($secrets.SqlWebPassword)
            SqlFormsUser                         = $($secrets.SqlFormsUser)
            SqlFormsPassword                     = $($secrets.SqlFormsPassword)
            SqlExmMasterUser                     = $($secrets.SqlExmMainUser)
            SqlExmMasterPassword                 = $($secrets.SqlExmMainPassword)
            SqlMessagingUser                     = $($secrets.SqlMessagingUser)
            SqlMessagingPassword                 = $($secrets.SqlMessagingPassword)
            # EXMCryptographicKey
            # EXMAuthenticationKey
            HostMappingName                      = $($DNSNames.CDDNS)
            DnsName                              = $($DNSNames.CDDNS)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
    'Prc' {
        $DeploymentParameters = @{
            Package                    = $($local.Package)
            LicenseFile                = $($local.LicenseFile)
            SiteName                   = $($local.SiteName)
            SSLCert                    = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert               = $($parameters.xConnectCertificateThumbPrint)
            XConnectCollectionService  = $($ServiceURLs.XConnectCollectionService)
            ReportingServiceApiKey     = $($secrets.ReportingServiceApiKey)
            SqlDbPrefix                = $($parameters.SCPrefix)
            SqlServer                  = $($parameters.SQLServer)
            SqlAdminUser               = $($secrets.SqlAdminUser)
            SqlAdminPassword           = $($secrets.SqlAdminPassword)
            SqlCoreUser                = $($secrets.SqlCoreUser)
            SqlCorePassword            = $($secrets.SqlCorePassword)
            SqlSecurityUser            = $($secrets.SqlSecurityUser)
            SqlSecurityPassword        = $($secrets.SqlSecurityPassword)
            SqlMasterUser              = $($secrets.SqlMainUser)
            SqlMasterPassword          = $($secrets.SqlMainPassword)
            SqlReportingUser           = $($secrets.SqlReportingUser)
            SqlReportingPassword       = $($secrets.SqlReportingPassword)
            SqlReferenceDataUser       = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword   = $($secrets.SqlReferenceDataPassword)
            SqlProcessingPoolsUser     = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword = $($secrets.SqlProcessingPoolsPassword)
            SqlProcessingTasksUser     = $($secrets.SqlProcessingTasksUser)
            SqlProcessingTasksPassword = $($secrets.SqlProcessingTasksPassword)
            # SitePhysicalRoot
            HostMappingName            = $($DNSNames.PrcDNS)
            DnsName                    = $($DNSNames.PrcDNS)
            SkipDatabaseInstallation   = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
    'Rep' {
        $DeploymentParameters = @{
            Package                = $($local.Package)
            LicenseFile            = $($local.LicenseFile)
            SSLCert                = $($parameters.InstanceCertificateThumbPrint)
            SqlDbPrefix            = $($parameters.SCPrefix)
            SiteName               = $($local.SiteName)
            # SitePhysicalRoot
            SqlCoreUser            = $($secrets.SqlCoreUser)
            SqlCorePassword        = $($secrets.SqlCorePassword)
            SqlSecurityUser        = $($secrets.SqlSecurityUser)
            SqlSecurityPassword    = $($secrets.SqlSecurityPassword)
            SqlMasterUser          = $($secrets.SqlMainUser)
            SqlMasterPassword      = $($secrets.SqlMainPassword)
            SqlReportingUser       = $($secrets.SqlReportingUser)
            SqlReportingPassword   = $($secrets.SqlReportingPassword)
            SqlServer              = $($parameters.SQLServer)
            ReportingServiceApiKey = $($secrets.ReportingServiceApiKey)
            HostMappingName        = $($DNSNames.RepDNS)
            DnsName                = $($DNSNames.RepDNS)
            # PackagesTempLocation
            # DownloadLocations

        }
    }
    'Collection' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix                    = $($parameters.SCPrefix)
            SqlAdminUser                   = $($secrets.SqlAdminUser)
            SqlAdminPassword               = $($secrets.SqlAdminPassword)
            SqlCollectionUser              = $($secrets.SqlCollectionUser)
            SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser               = $($secrets.SqlMessagingUser)
            SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
            SqlServer                      = $($parameters.SQLServer)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            HostMappingName                = $($DNSNames.CollectionDNS)
            DnsName                        = $($DNSNames.CollectionDNS)
            SkipDatabaseInstallation       = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
        $skip = @(
            'CreateShards'
            'CleanShards'
            #'CreateShardApplicationDatabaseServerLoginSqlCmd'
            #'CreateShardManagerApplicationDatabaseUserSqlCmd'
            #'CreateShard0ApplicationDatabaseUserSqlCmd'
            #'CreateShard1ApplicationDatabaseUserSqlCmd'
        )
    }
    'CollectionSearch' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix                    = $($parameters.SCPrefix)
            SolrCorePrefix                 = $($parameters.SolrCorePrefix)
            SqlCollectionUser              = $($secrets.SqlCollectionUser)
            SqlCollectionPassword          = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser         = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword     = $($secrets.SqlProcessingPoolsPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser               = $($secrets.SqlMessagingUser)
            SqlMessagingPassword           = $($secrets.SqlMessagingPassword)
            SqlServer                      = $($parameters.SQLServer)
            SolrUrl                        = $($parameters.SolrUrl)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            HostMappingName                = $($DNSNames.CollectionSearchDNS)
            DnsName                        = $($DNSNames.CollectionSearchDNS)
            # PackagesTempLocation
            # DownloadLocations
        }
        $skip = @(
            # 'DownloadWDP'
            # 'CreatePaths'
            # 'CreateAppPool'
            # 'SetAppPoolCertStorePermissions'
            # 'CreateWebsite'
            # 'StopWebsite'
            # 'StopAppPool'
            # 'StopService'
            # 'RemoveService'
            # 'RemoveDefaultBinding' 
            # 'CreateBindingsWithThumbprint'
            # 'SetClientCertificatePermissions'
            # 'CreateHostHeader'
            # 'SetPermissions'
            # 'InstallWDP'
            # 'SetLicense'
            # 'CreateBindingsWithDevelopmentThumbprint'
            # 'StartAppPool'
            # 'StartWebsite'
            # 'SetServicesCertStorePermissions'
            # 'CreateServiceLogPath'
            # 'SetIndexWorkerServiceLicense'
            # 'SetServicePermissions'
            # 'InstallService'
            # 'StartService'
            'ConfigureSolrSchemas'
        )
    }
    'MarketingAutomationReporting' {
        $DeploymentParameters = @{
            Package                        = $($local.Package)
            LicenseFile                    = $($local.LicenseFile)
            SiteName                       = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                        = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                   = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix                    = $($parameters.SCPrefix)
            SqlReferenceDataUser           = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword       = $($secrets.SqlReferenceDataPassword)
            SqlMarketingAutomationUser     = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword = $($secrets.SqlMarketingAutomationPassword)
            SqlServer                      = $($parameters.SQLServer)
            XConnectEnvironment            = $($parameters.Environment)
            XConnectLogLevel               = $($parameters.LogLevel)
            HostMappingName                = $($DNSNames.MarketingAutomationReportingDNS)
            DnsName                        = $($DNSNames.MarketingAutomationReportingDNS)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
    'MarketingAutomation' {
        $DeploymentParameters = @{
            Package                         = $($local.Package)
            LicenseFile                     = $($local.LicenseFile)
            SiteName                        = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                         = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                    = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix                     = $($parameters.SCPrefix)
            SqlAdminUser                    = $($secrets.SqlAdminUser)
            SqlAdminPassword                = $($secrets.SqlAdminPassword)
            SqlCollectionUser               = $($secrets.SqlCollectionUser)
            SqlCollectionPassword           = $($secrets.SqlCollectionPassword)
            SqlProcessingPoolsUser          = $($secrets.SqlProcessingPoolsUser)
            SqlProcessingPoolsPassword      = $($secrets.SqlProcessingPoolsPassword)
            SqlReferenceDataUser            = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword        = $($secrets.SqlReferenceDataPassword)
            SqlMarketingAutomationUser      = $($secrets.SqlMarketingAutomationUser)
            SqlMarketingAutomationPassword  = $($secrets.SqlMarketingAutomationPassword)
            SqlMessagingUser                = $($secrets.SqlMessagingUser)
            SqlMessagingPassword            = $($secrets.SqlMessagingPassword)
            SqlServer                       = $($parameters.SQLServer)
            XConnectCollectionSearchService = $($ServiceURLs.XConnectCollectionSearchService) # "https://XConnectCollectionSearch"
            XConnectReferenceDataService    = $($ServiceURLs.XConnectReferenceDataService) # "https://XConnectReferenceData"
            XConnectEnvironment             = $($parameters.Environment)
            XConnectLogLevel                = $($parameters.LogLevel)
            HostMappingName                 = $($DNSNames.MarketingAutomationDNS)
            DnsName                         = $($DNSNames.MarketingAutomationDNS)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
    'ReferenceData' {
        $DeploymentParameters = @{
            Package                  = $($local.Package)
            LicenseFile              = $($local.LicenseFile)
            SiteName                 = $($local.SiteName)
            XConnectCert             = $($parameters.xConnectCertificateThumbPrint)
            XConnectEnvironment      = $($parameters.Environment)
            XConnectLogLevel         = $($parameters.LogLevel)
            DnsName                  = $($DNSNames.ReferenceDataDNS)
            SqlDbPrefix              = $($parameters.SCPrefix)
            SqlServer                = $($parameters.SQLServer)
            SqlAdminUser             = $($secrets.SqlAdminUser)
            SqlAdminPassword         = $($secrets.SqlAdminPassword)
            SqlReferenceDataUser     = $($secrets.SqlReferenceDataUser)
            SqlReferenceDataPassword = $($secrets.SqlReferenceDataPassword)
            SkipDatabaseInstallation = $($local.SkipDBInstallOnRoles)
        }
        $skip = @(
            # 'DownloadWDP'
            # 'CreatePaths'
            # 'CreateAppPool'
            # 'SetAppPoolCertStorePermissions'
            # 'CreateWebsite'
            # 'StopWebsite'
            # 'StopAppPool'
            # 'RemoveDefaultBinding'
            # 'CreateBindingsWithThumbprint'
            # 'SetClientCertificatePermissions'
            # 'CreateHostHeader'
            # 'SetPermissions'
            # 'InstallWDP'
            # 'SetLicense'
            # 'CreateBindingsWithDevelopmentThumbprint'
            # 'StartAppPool'
            # 'StartWebsite'
        )
    }
    'CortexProcessing' {
        $DeploymentParameters = @{
            Package                     = $($local.Package)
            LicenseFile                 = $($local.LicenseFile)
            SiteName                    = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                     = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert                = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix                 = $($parameters.SCPrefix)
            SqlAdminUser                = $($secrets.SqlAdminUser)
            SqlAdminPassword            = $($secrets.SqlAdminPassword)
            SqlMessagingUser            = $($secrets.SqlMessagingUser)
            SqlMessagingPassword        = $($secrets.SqlMessagingPassword)
            SqlProcessingEngineUser     = $($secrets.SqlProcessingEngineUser)
            SqlProcessingEnginePassword = $($secrets.SqlProcessingEnginePassword)
            SqlReportingUser            = $($secrets.SqlReportingUser)
            SqlReportingPassword        = $($secrets.SqlReportingPassword)
            SqlServer                   = $($parameters.SQLServer)
            XConnectCollectionService   = $($ServiceURLs.XConnectCollectionService)
            XConnectSearchService       = $($ServiceURLs.XConnectSearchService)
            XConnectEnvironment         = $($parameters.Environment)
            XConnectLogLevel            = $($parameters.LogLevel)
            # MachineLearningServerUrl
            # MachineLearningServerBlobEndpointCertificatePath
            # MachineLearningServerBlobEndpointCertificatePassword
            # MachineLearningServerTableEndpointCertificatePath
            # MachineLearningServerTableEndpointCertificatePassword
            # MachineLearningServerEndpointCertificationAuthorityCertificatePath
            HostMappingName             = $($DNSNames.CortexProcessingDNS)
            DnsName                     = $($DNSNames.CortexProcessingDNS)
            SkipDatabaseInstallation    = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
    'CortexReporting' {
        $DeploymentParameters = @{
            Package                  = $($local.Package)
            LicenseFile              = $($local.LicenseFile)
            SiteName                 = $($local.SiteName)
            # SitePhysicalRoot
            SSLCert                  = $($parameters.InstanceCertificateThumbPrint)
            XConnectCert             = $($parameters.xConnectCertificateThumbPrint)
            SqlDbPrefix              = $($parameters.SCPrefix)
            SqlAdminUser             = $($secrets.SqlAdminUser)
            SqlAdminPassword         = $($secrets.SqlAdminPassword)
            SqlReportingUser         = $($secrets.SqlReportingUser)
            SqlReportingPassword     = $($secrets.SqlReportingPassword)
            SqlServer                = $($parameters.SQLServer)
            XConnectEnvironment      = $($parameters.Environment)
            XConnectLogLevel         = $($parameters.LogLevel)
            HostMappingName          = $($DNSNames.CortexReportingDNS)
            DnsName                  = $($DNSNames.CortexReportingDNS)
            SkipDatabaseInstallation = $($local.SkipDBInstallOnRoles)
            # PackagesTempLocation
            # DownloadLocations
        }
    }
}

If ($Role -ne 'DbResources') {
    Push-Location $($parameters.SCInstallRoot)
    $internalDNSType = (Get-SSMParameter -Name "/$SCQSPrefix/user/InternalPrivateDNS").Value
    if ($Role -eq 'MarketingAutomation' -And $internalDNSType -eq 'True') {
        New-AWSQuickStartResourceSignal -Stack $StackName -Region $Region -Resource "MarketingAutomationASG"
        Write-AWSQuickStartStatus
    }
    Install-SitecoreConfiguration @DeploymentParameters -Path $($local.jsonPath) -Skip $skip -Verbose *>&1 | Tee-Object "$localLogPath\$Role.log"
    $LogGroupName = "$SCQSPrefix-$Role"
    $LogStreamName = "$Role-RoleInstallation-" + (Get-Date (Get-Date).ToUniversalTime() -Format "MM-dd-yyyy" )
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString $(Get-Content -Path "$localLogPath\$Role.log" -raw)
    # Setting permissions for AppPool Identity in Administrators
    $AppPoolSiteName = $DeploymentParameters.SiteName
    Add-LocalGroupMember -Group "Administrators" -Member "IIS AppPool\$AppPoolSiteName"
    
    $Site = Get-Website -Name $DeploymentParameters.SiteName
    $AppPool = Get-ItemProperty ("IIS:\AppPools\$AppPoolSiteName")
    # Configure Application Pool StartMode
    $CurrentStratMode = $AppPool.startMode
    if($CurrentStratMode -ne "AlwaysRunning")
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Current StartMode: $CurrentStratMode"
            $AppPool | Set-ItemProperty -name "startMode" -Value "AlwaysRunning"
            $AppPool = Get-ChildItem IIS:\AppPools\ | Where-Object { $_.Name -eq $Site.applicationPool }
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "StartMode set to $CurrentStratMode"
        } 
        else 
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "StartMode is : $CurrentStratMode. No update required"
        }

    #Configure Application Pool Idle Timeout value
    $currentIdleTimeout = Get-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") -Name processModel.idleTimeout.value
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout value is : $currentIdleTimeout"
    # Set to 30 min
    $SitecoreIdleTimeout = '0'
    $SitecoreIdleTimeoutAction = 'Suspend'
    $userProfile = "True"
    $maxProcesses = 1
    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") -Name processModel.idleTimeout -value ( [TimeSpan]::FromMinutes($SitecoreIdleTimeout))
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout value updated to : $SitecoreIdleTimeout"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.idleTimeoutAction -Value $SitecoreIdleTimeoutAction
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Idle Timeout Action updated to : $SitecoreIdleTimeoutAction"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.loadUserProfile -Value $userProfile
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Load user profile updated to : $userProfile"

    Set-ItemProperty ("IIS:\AppPools\$AppPoolSiteName") processModel.maxProcesses -Value $maxProcesses
    Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "MaxProcess updated to : $maxProcesses"

    $currentSitePreload = (Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value
    # Enable Preload
    if(!(Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value) 
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Current Site Preload : $currentSitePreload"
            Set-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled -Value True
            $newSitePreload = (Get-ItemProperty "IIS:\Sites\$AppPoolSiteName" -Name applicationDefaults.preloadEnabled).Value
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Site Preload update to: $newSitePreload"
        } 
        else
        {
            Write-AWSQuickStartCWLogsEntry -logGroupName $LogGroupName -LogStreamName $LogStreamName -LogString "Site Preload is : $CurrentStratMode. No update required"
        }
    Pop-Location
}