<#
  .SYNOPSIS
  Gets information from the Ultopro database export, and Epic database match, and attempts to create a user account and notify stake holders.

  .DESCRIPTION
  This script searches a database for either new accounts, based on day or an ID.
  It takes the information from the database, forms what the username should be, creates the account, and attempt to send a messsage.
  The message can be sent to any number of individuals that need to know about the account creation.

  .NOTES
  This script requires powershell 5.1

  .PARAMETER Days
  Specify number of days back in time to look for new accounts.
  This information is used to filter what is pulled from the database by date.

  .EXAMPLE
  Get-NewEmployees -Day 1
#>

#Requires -Version 5.1

# Script Parameters
param(
  [System.Boolean] $MakeCreds = $false
) # END params

BEGIN {
  #####
  # Set Powershell to run in full mode
  #####
  if (($ExecutionContext.SessionState.LanguageMode) -eq "ConstrainedLanguage") {
    $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'
  } # End if

  #####
  # Install Dependancies
  #####
  # SQL Management and interaction modules
  #if (!(Get-Module -ListAvailable -Name "SqlServer")) {
  #  Install-Module -Name SqlServer
  #} # END if

  # Used to perform different kinds of logging
  if (!(Get-Module -ListAvailable -Name "Logging")) {
    Install-Module Logging
  } # END if

  # Allows for the ability to interact with Active Directory
  if (!(Get-Module -ListAvailable -Name "ActiveDirectory")) {
    Install-Module ActiveDirectory
  } # END if

  # Import Dependancies
  #Import-Module SqlServer # Requred to interact with database servers
  Import-Module Logging # Required to facilitate a log file
  Import-Module ActiveDirectory # Required to interact with Active Directory

  #####
  # Helper path variables
  #####
  $ScriptPath = "$PSScriptRoot\.." # Path where the script lives
  $ScriptLogs = "$ScriptPath\logs" # Path to where log will be contained
  $LogName = "EmpOnboarding" # Name of the log file to create
  $LogFile = "$ScriptLogs\$($LogName)_%{+%Y%m%d}.log" # Generate log location and name by date
  $CacheName = "Get-NewEmployees.cache" # Location where cache file will live
  $CacheFile = "$Scriptpath\$CacheName" # Creating the full cache file path

  #####
  # Configure log provider
  #####
  $SetLoggingProvider = @{
    Path = $LogFile
  } # END SetLoggingProvider

  # Set the log provider
  try {
    # Configure the logger to output to a file
    Add-LoggingTarget -Name File -Configuration $SetLoggingProvider
  } # END try
  catch {
    # Fail the script if it cannot log anything
    Write-Warning "Logging provider could not be confgured. There is an issue with using Powershell version 7. Logs will not be captured. Script exiting."
    Write-Host "If using VSCode for testing, edit settings :: PowerShell.powerShellAdditionalExePaths. Add the exe path and version name. Set the settings powershell.powerShellDefaultVersion to the version name for 5.1. Set terminal.integrated.shell.windows to powershell 5.1"
    Exit
  } # END try catch

  #####
  # Setup system functions
  #####
  Function Start-LogRotation ($Path) {
    <#
    .SYNOPSIS
    Perform log rotation
    .DESCRIPTION
    Takes a path and finds all files older than 30 days.
    .EXAMPLE
    Start-LogRotation -Path "SomeFolder"
    #>
    $FileCount
    try {
      # Get the files that already exist for logging older that 30 days
      $Files = Get-ChildItem -Path $Path -Filter "$LogName*" | Where-Object { $_.LastWriteTime -lt (get-Date).AddDays(-30) }
      $FileCount = ($Files | Measure-Object).count # Count the file number for logging

      if ($FileCount) {
        # If any old files are detected
        $Files | Remove-Item # Remove these files
        Write-Log -Level INFO -Message "{0} :: Performed log rotation and deleted {1} files" -Arguments $($MyInvocation).MyCommand.Name, $FileCount
      } # END if
      else {
        # Otherwise end this section and log
        Write-Log -Level INFO -Message "{0} :: No logs needed to be rotated." -Arguments $($MyInvocation).MyCommand.Name
      } # END if else
    } # END try
    catch {
      # If everything fails exit the application
      Write-Log -Level ERROR -Message "{0} :: Log rotation could not be performed. Check settings, current log path [{1}]" -Arguments $($MyInvocation).MyCommand.Name, $Path
      Exit
    } # END try catch
  } # END Start-LogRotation

  Function New-SecureString ($Output) {
    <#
      .SYNOPSIS
      Create a secure string file and place it in a file.

      .DESCRIPTION
      The secure string file is individual to the computer that produces it.
      Later this file will be used for service account credentials.

      .EXAMPLE
      New-SecureString -Output ".\SecureString.txt"
    #>

    # Promp for a password to generate the secure string file
    $Secure = Read-Host -Prompt "Enter service account password" -AsSecureString

    try {
      # Attempt to create the encrypted password file
      $Encrypted = ConvertFrom-SecureString -SecureString $Secure
      $Encrypted | Set-Content "$PSScriptRoot\..\Secure_Pass.txt"

      Write-Log "{0} :: Created a powershell secure string password" -Arguments $($MyInvocation).MyCommand.Name
    } # END try
    catch {
      # Exit application if a file could not be created
      Write-Log -Level ERROR -Message "{0} :: Could not create secure password file with supplied input. Exiting" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END New-SecureString

  Function Read-SecureString ($File) {
    <#
      .SYNOPSIS
      Read the outputted SecureString file to use in other functions.

      .DESCRIPTION
      After the file is created it must be imported in a string format. 
      The encrypted file can later be used with the PS Credential provider.

      .EXAMPLE
      Read-SecureString -File ".\SecureString.txt"
    #>
    try {
      # Get the content of the encrypted password file
      $Encrypted = Get-Content $File
    } # END try
    catch {
      # Create an error log if it fails
      Write-Log -Level ERROR -Message "{0} :: Could not read secure string to write credential" -Arguments $($MyInvocation).MyCommand.Name
    } # END try catch
    
    # Make the encrypted password file available for credentals
    $Secure = ConvertTo-SecureString -String $Encrypted
    Return $Secure
  } # END Read-SecureString

  Function New-Credential ($Username, [SecureString] $Password) {
    <#
      .SYNOPSIS
      Take the imported secure string and create a PS Credential.

      .DESCRIPTION
      Generate a PS Credential by using the imported secure string.
      The PS Credential will later be used when interacting with Active Directory.

      .EXAMPLE
      New-Credential -Username $Username -Password $Password
    #>
    try {
      # Create a powershell credential with the service account and encrypted password file
      $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $Password
      Write-Log "{0} :: Created credential object for service account {1}" -Arguments $($MyInvocation).MyCommand.Name, $Username
    } # END try
    catch {
      Write-Log -Level ERROR -Message "{0} :: Could not create credential for $Username" -Arguments $($MyInvocation).MyCommand.Name
    } # END try catch

    Return $Credential
  } # END New-Credential

  Function Get-Cache ($ExpirationDays) {
    <#
      .SYNOPSIS
      Creates a cache file that can expire as required

      .DESCRIPTION
      Generate a PS Credential by using the imported secure string.
      The PS Credential will later be used when interacting with Active Directory.

      .EXAMPLE
      New-Credential -Username $Username -Password $Password
    #>

    # Time at which cache is set to exipire
    $CacheTime = New-TimeSpan -days $ExpirationDays

    Write-Log -Level INFO -Message "{0} :: Attempting to create cache file" -Arguments $($MyInvocation).MyCommand.Name

    if (Test-Path -Path $CacheFile) {
      # Check if cache file exists
      $CreationTime = (get-Item $CacheFile) # If it does, get the file information
      if (((Get-date) - $CreationTime.CreationTime) -gt $CacheTime) {
        # If file age is old
        Write-Log -Level INFO -Message "{0} :: Cache file has expired" -Arguments $($MyInvocation).MyCommand.Name

        Remove-Item -Path $CacheFile -Force # Remove the cache file
        New-item -Path $ScriptPath -Name $CacheName -ItemType File # Replace with a new file

        Write-Log -Level INFO -Message "{0} :: Created new cache file named $CacheName" -Arguments $($MyInvocation).MyCommand.Name
      } # END if
    } # END if
    else {
      # If the file does not exist
      New-item -Path $ScriptPath -Name $CacheName -ItemType File # Create the cache
      Write-Log -Level INFO -Message "{0} :: Created new cache file with name $CacheName" -Arguments $($MyInvocation).MyCommand.Name
    } # END if else

    # Export the cache file
    Return Import-CSV $CacheFile
  } # END Get-Cache

  Function Get-MailTemplate ($Config, $Subject, $Body, $To) {
    <#
      .SYNOPSIS
      Create a email message, using body content and send.

      .DESCRIPTION
      Using the report body from another function, craft a mail messge.
      Certian settings are preconfigured via the config object.

      .EXAMPLE
      Get-mailTemplate -Config $Config -Subject "my message" -Body "Message Body" -To "Someone@Something.org"
    #>
    try {
      # Attempt to create the body of the mail message
      Write-Log -Level INFO -Message "{0} :: Attempting to send mail message :: SUBJECT {1}" -Arguments $($MyInvocation).MyCommand.Name, $Subject
      if ($null -eq $Body) {
        # If the body is null exit
        Write-Log -Level INFO -Message "{0} :: No data was produced for body. Exiting function :: SUBJECT {1}" -Arguments $($MyInvocation).MyCommand.Name, $Subject
        Return
      } # END if
      else {
        # If the body is not null then send the mail message
        Write-Log -Level INFO -Message "{0} :: Attempting to send mail message :: SUBJECT {1}" -Arguments $($MyInvocation).MyCommand.Name, $Subject
        Send-MailMessage -SmtpServer $Config.SmtpServer -From $Config.SmtpFrom -Port <REDACTED> -To $To -Subject $Subject -BodyAsHtml $Body
      } # END if else
    } # END tru
    catch {
      # If there was an error sending the message exit the application
      Write-Log -Level ERROR -Message "{0} :: Could not send mail message" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-MailTemplate

  Function Get-MailBody ($Data, $ReportName, $Description) {
    <#
      .SYNOPSIS
      Create a report to send with emails.

      .DESCRIPTION
      Imports table data and converts it to html.
      Modifies the HTML to create the structure of a report.

      .EXAMPLE
      Get-MailBody -Data $Tables -ReportName "Title of Report" -Description "Supporting information"
    #>

    # Create the body structure using HTML and a multiline string
    $EmailBody = @"
<table style="width: 68%" style="border-collapse: collapse; border: 1px solid #008080;">
 <tr>
    <td colspan="2" bgcolor="#008080" style="color: #FFFFFF; font-size: large; height: 35px;"> 
        Automated Script - $ReportName  
    </td>
        <td colspan="2" bgcolor="#008080" style="color: #FFFFFF; height: 35px;"> 
        $Description 
    </td>
 </tr>
</table>
"@

    If ($Data) {
      # If the data for the report exists
      $EmailBody += ($Data | ConvertTo-HTML) # Add it to the end of the body
      Return $EmailBody # Export Body
    } # END if
    Else {
      # Return nothing if no data is in the input
      Return $null
    } # END if else
  } # END Get-MailBody

  #####
  # Setup application functions
  # SQL Query
  #####
  Function Get-LastChanged ($Days, $Config) {
    <#
      .DESCRIPTION
      Gets all accounts that were modified in so many days from today's date.
      Based on the PersDateChanged table.

      .EXAMPLE
      Get-LastChanged -Days 1 -Config $Config
    #>
    $Table = <REDACTED> # Table containing employee info from UKG
    $DateField = <REDACTED> # Attribute used to filter by when changed

    # Attributes from the table to pull
    $SelectedData = <REDACTED>

    # SQL query to select accounts by last changed
    $Query = "Select $SelectedData from $Table where $DateField >= GETDATE() - $Days"

    Try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Config.Database   `
        -Query $Query 
    } # END try
    catch {
      # If the query fails exit the application
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-LastChanged

  Function Get-Terminated ($Days, $Config) {
    <#
      .DESCRIPTION
      Gets all terminalted persons within so many days.
      Pased on the PersDateChanged Field

      .EXAMPLE
      Get-Terminated -Days 1 -Config $Config
    #>
    $Table = <REDACTED> # Table containing employee info from UKG
    $DateField = <REDACTED> # Attrubute used to filter by last changed

    # Attrubutes to select for the SQL query
    $SelectedData = <REDACTED>

    # SQL query to get the terminated users within a date range from now
    $Query = "Select $SelectedData from $Table where $DateField >= GETDATE() - $Days AND <REDACTED> = 'Terminated'"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Config.Database  `
        -Query $Query 
    } # END try
    catch {
      # Exit the application if the SQL query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-Terminated

  Function Get-LastCreated ($Days, $Config) {
    <#
      .DESCRIPTION
      Get the people who were created in the last number of days.
      Based on the PersDateCreated field.

      .EXAPMLE
      Get-LastCreated -Days 1 -Config $Config
    #>
    $Table = <REDACTED> # Table containing employee data from UKG
    $DateField = <REDACTED> # Attribute to filter by when the account was created

    # Attributes to select from the SQL query
    $SelectedData = <REDACTED>

    # SQL query to get the accounts created from date range to now
    $Query = "Select $SelectedData from $Table where $DateField >= GETDATE() - $Days"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Config.Database  `
        -Query $Query 
    } # END try
    catch {
      # If query fails exit the application
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END catch
  } # END Get-LastCreated

  Function Get-PersonByID ($empID, $Config) {
    <#
      .DESCRIPTION
      Gets the information about a single employee.
      Based on the EecEmpNo field to filter by ID.

      .EXAMPLE
      Get-PersonByID -empID <REDACTED> -Config $Config
    #>
    Write-Log -Level INFO -Message "{0} :: Attempting to get {1} from SQL table." -Arguments $($MyInvocation).MyCommand.Name, $empID

    $Table = <REDACTED> # Table with Employee data from UKG
    $Filter = "<REDACTED> = '{0}'" -f $empID # Filter by the employee ID of an account

    # Attributes select for the SQL query
    $SelectedData = <REDACTED>

    # SQL query to get a single account by employee ID
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attepmt to run the SQL query
      Write-Log -Level INFO -Message "{0} :: Successfully got {1} from SQL." -Arguments $($MyInvocation).MyCommand.Name, $empID
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Config.Database  `
        -Query $Query
    } # END try
    catch {
      # Exit the application if hte SQL query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-PersonByID

  #####
  # Setup Application Functions
  # User Properties
  #####
  Function Get-Username ($Person) {
    <#
      .DESCRIPTION
      Attempts to figure out what the username of a person should be.
      Constructed by taking the:
      1. First letter of the first name.
      2. First 5 letters of the last name.
      3. Last 2 digits of the EmployeeID.
      If the person has less than 5 characters, in the last name, it will take whatever is available in the last name.
      If the person has special characters in the name, those characters will be removed before processing.

      .EXAMPLE
      Get-Username -Person $Person
    #>
    try {
      # Attempt to the the expected username of an account
      $EmpID = $Person.EecEmpNo # Prep the employee number
      $Firstname = ($Person.EepnameFirst) -replace '[^a-zA-Z]', '' # Replace bad characters
      $Lastname = ($Person.EepNameLast) -replace '[^a-zA-Z]', '' # Replcae bad characters

      # Get the first letter of the first name
      $FirstSection = $Firstname.Substring(0, 1)

      If ($LastName.Length -le 5) {
        # If the last name is less than 5
        # Output the whole last name
        $SecondSection = $LastName
      } # END if
      Else {
        # Otherwise take the first 5 characters of the last name
        $SecondSection = $Lastname.Substring(0, 5)
      } # END if else

      # Get the last 2 characters of the employee ID
      $ThirdSection = $EmpID.Substring($EmpID.Length - 2)

      # Return a formatted string representing the user name
      Return "{0}{1}{2}" -f $FirstSection, $SecondSection, $ThirdSection
    } # END try
    catch {
      # Exit the application if the username could not be created
      Write-Log -Level ERROR -Message "{0} :: Could not create a username for ID {1}. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name, $EmpID
      Exit
    } # End try catch

  } # END Get-Username

  Function Get-EmailAddress ($Person) {
    <#
      .DESCRIPTION
      Attempts to construct the email address based upon the username.
      This must run with after, and with, the input of Get-Username.

      .Example
      Get-EmailAddress -Person $Person
    #>
    <#
    if ($Person.EepAddressEmail) {
      $Username = ($Person.<REDACTED>).Split('@')[0]
    }
    else {
      $Username = $Person.EecMailstop
    }
    #>

    if ([string]::IsNullOrEmpty($Person.<REDACTED>)) {
      $Username = $Person.<REDACTED>
    }
    else {
      $Username = ($Person.<REDACTED>).Split('@')[0]
    }
    
    # Return the formatted string of the initial username
    Return "{0}@womans.org" -f $Username
  } # END Get-EmailAddress

  Function Get-Initials ($Person) {
    <#
      .DESCRIPTION
      Attempts to construct the individual's initials from the fist, middle, and last name.
      If any name is missing it will not be included in the final result.

      .EXAMPLE
      Get-Initials -Person $Person
    #>
    $Firstname = $Person.<REDACTED># Prep first name
    $Middlename = $Person.<REDACTED> # Prep middle name
    $Lastname = $Person.<REDACTED> # Prep last name

    # Get the first letter of the first name
    $FirstSection = $Firstname.Substring(0, 1)

    if ([string]::IsNullOrEmpty($MiddleName)) {
      # If the middle name is null
      # Blank it out to remove bad characters or information
      $SecondSection = ""
    } # END if
    else {
      # Otherwise get the first letter of the middle name
      $SecondSection = $Middlename.Substring(0, 1)
    } # END if else
        
    if ($Lastname) {
      # If the last name exists
      # Get the first letter of the last name
      $ThirdSection = $LastName.Substring(0, 1) 
    } # END if
    else {
      # Otherwise blank out the last name
      $ThirdSection = ""
    } # END if else

    # Return formatted string of what the initials are
    Return "{0}{1}{2}" -f $FirstSection, $SecondSection, $ThirdSection
  } # END Get-Initials

  Function Get-Password {
    <#
      .DESCRIPTION
      Attempts to create a password that is human readable.
      The password character count can be modified within this function.
      Change the Get-Random count parameter to the required password length.
      This function does not require any input.

      .EXAMPLE
      Get-Password
    #>
    try {
      # Attempt to create a initial password for the account
      # Password generator will not make complicated passwords for initial account creation
      $Password = -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count 12  | ForEach-Object { [char]$_ })

      # Output the password result
      Return $Password
    } # END try
    catch {
      # Exit the application if a password could not be generated
      Write-Log -Level ERROR -Message "{0} :: Password could not be created. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-Password

  #####
  # Secton for Active Directory creation
  #####
  Function Get-DepartmentOU ($Department) {
    <#
    .DESCRIPTION
    Get the department OU that the new account should belong to.
    Will create the OU if it does not already exist.
    If it does exist, output the full DN of the OU.
            
    .EXAMPLE
    Get-DepartmentOU -Department "Information Systems"
    #>

    # OU Path where all user accounts will be created for persons
    $BasePath = <REDACTED>

    $DepartmentOU = "OU=$Department,$BasePath" # Constructing the OU path containing the department
    $OUExists = [adsi]::Exists("LDAP://$DepartmentOU") # Checking if this OU already exists

    Switch ($OUExists) {
      # Boolean state of the OU if exists
      $True {
        # Output the full path of the OU with department
        Return $DepartmentOU
      } # END TRUE
      $False {
        # Otherwise create the OU
        Try {
          # Attempt to create the OU in the base path location
          New-ADOrganizationalUnit -Name $Department -Path <REDACTED>
          Write-Log -Level INFO -Message "{0} :: Created the department OU $Department" -Arguments $($MyInvocation).MyCommand.Name
        } # END try
        Catch {
          # Exit the application if it failed to create the OU
          Write-Log -Level ERROR -Message "{0} :: Could not create $Deparment OU in :: $BasePath :: Exiting" -Arguments $($MyInvocation).MyCommand.Name
          Exit
        } # END try catch
      } # END FALSE
    } # END switch

    Return $DepartmentOU
  } # END Get-DepartmentOU

  Function New-AdAccount ($Person, $Location) {
    <#
    .DESCRIPTION
    Attempts to make the new user account in Active Directory.
    This account is made with information from UKG.
    Group access is setup to be basic.
            
    .EXAMPLE
    New-AdAccount -Person $Person -Location $OU
    #>

    # Convert the password to a useable format
    $Password = ConvertTo-SecureString -String $Person.InitialPassword -AsPlainText -Force

    Try {
      # Attempt to get the middle initial of the person
      $MiddleInitial = $($Person.MiddleName).substring(0, 1)
    } # END try
    Catch {
      # Otherwise blank out the middle initial
      $MiddleInitial = ""
    } # END try catch
    
    # Formatted string of what the display name should be of the account
    $Username = $Person.<REDACTED>

    $DisplayName = $("{0},{1}") -f $Person.<REDACTED>, $Person.<REDACTED>
    $Name = $("{0},{1} {2}" -f $Person.<REDACTED>, $Person.<REDACTED>, $MiddleInitial).Trim().ToUpper()
    $UPN = "{0}@<REDACTED>" -f $Username

    try {
      New-ADUser -Name $Name `
        -Path $OU `
        -SamAccountName $Username `
        -AccountPassword $Password `
        -DisplayName $DisplayName `
        -Enabled $True `
        -CannotChangePassword $False `
        -City $Person.<REDACTED> `
        -Company $Person.<REDACTED> `
        -Title $Person.<REDACTED> `
        -Department $Person.<REDACTED> `
        -Description $Person.<REDACTED> `
        -EmployeeID $Person.<REDACTED> `
        -EmailAddress $Person.<REDACTED> `
        -EmployeeNumber $Person.<REDACTED> `
        -GivenName $Person.<REDACTED> `
        -Surname $Person.<REDACTED> `
        -Initials $Person.<REDACTED> `
        -State $Person.<REDACTED> `
        -Division $Person.<REDACTED> `
        -OtherName $Person.<REDACTED> `
        -UserPrincipalName $UPN

      Write-Log -Level INFO -Message "{0} :: AD Account created for {1} with username {2}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>, $Username
    }
    catch {
      Write-Log -Level WARNING -Message "{0} :: Could not create AD Account for {1} :: {2}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>, $Error[0]
    }


    # Set the account manager
    try {
      Set-ADuser $Username -Manager $Person.<REDACTED>

      Write-Log -Level INFO -Message "{0} :: Assigned supervisor for {1} with username {2}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>, $Person.<REDACTED>
    }
    catch {
      Write-Log -Level WARNING -Message "{0} :: Could not assign supervisor for {1} :: {2}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>, $Error[0]
    }

    try {
      Add-ADGroupMember -Identity <REDACTED> -Members $Username
      Add-ADGroupMember -Identity <REDACTED> -Members $Username
      Add-ADGroupMember -Identity <REDACTED> -Members $Username

      Write-Log -Level INFO -Message "{0} :: Added initial required groups for {1}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>
    }
    catch {
      Write-Log -Level WARNING -Message "{0} :: Could not assign groups for {1} :: {2}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>, $Error[0]
    }

    $MessageBody = @"
A new account has been created for a team member under your supervision.<br><br>
The information for this account is:<br>
Firstname : {0}<br>
LastName  : {1}<br>
Username  : {2}<br>
Password  : {3}<br>
"@ -f $Person.<REDACTED>, $Person.<REDACTED>, $Username, $Person.InitialPassword

    If ($Person.SupervisorMailStop) {
      $Supervisor = Get-ADUser $Person.<REDACTED> -Properties mail
      Get-MailTemplate -Config $Config -Subject "New Assigned User" -To $Supervisor.Mail -Body $MessageBody
    }

    # TODO Email Manager
    Return $OU
  } # END New-AdAccount

  Function Get-UserGUID ($Person) {
    Try {
      Write-Log -Level INFO -Message "{0} :: Got the GUID for {1}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>
      $User = Get-ADUser $Person -Properties ObjectGUID
      Return $User.ObjectGUID
    }
    Catch {
      Write-Log -Level ERROR -Message "{0} :: Failed to get GUID for {1}" -Arguments $($MyInvocation).MyCommand.Name, $Person.<REDACTED>
    }
  }

  #####
  # Section for getting information from Epic
  #####
  Function Get-EpicJobMap ($Person) {
    <#
      .DESCRIPTION
      By using the employeeID, query the employee database for Epic information.
      Output will prodice a match map for getting more Epic information later.
            
      .EXAMPLE
      Get-EpicJobMap -Person $Person
    #>
    $Database = <REDACTED> # Database contianing Epic information
    $Table = <REDACTED> # Table where this Epic information lives

    # Filter to match on the title and department of an account
    $Filter = "<REDACTED> = '{0}' AND <REDACTED>= '{1}'" -f $Person.<REDACTED>, $Person.<REDACTED>

    # Selected attributes from the query
    $SelectedData = <REDACTED>

    # Query to get all attributes where both the job title and department match
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attempt to run the query
      $Results = Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Database  `
        -Query $Query 

      Return $Results | Get-Unique 

    } # END try
    catch {
      # Exit the application if the query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END catch
  } # END get-EpicJobMap

  Function Get-MainTemplate ($Person, $MainMap) {
    <#
      .DESCRIPTION
      Find the main template by using the previously created match map.
      This will output the person's Main Epic Template.

      .EXAMPLE
      Get-MainTemplate -Person $Person -MainMap $MainMap
    #>
    $Database = <REDACTED> # Database containing Epic information
    $Table = <REDACTED> # Table where Epic information lives

    # Filter to match on job title and role
    $Filter = "Title = '{0}' AND Job = '{1}'" -f $Person.<REDACTED>, $MainMap.<REDACTED>

    # Selected attributes from the SQL query
    $SelectedData = <REDACTED>

    # Query to filter data based on the job title and job role
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Database  `
        -Query $Query 
    } # END try
    catch {
      # Exit the application if the query fails to run
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-MainTemplate

  Function Get-SubTemplate ($Person, $MainMap) {
    <#
      .DESCRIPTION
      Get the subtemplate of the account via the previously created main map.

      .EXAMPLE
      Get-SubTemplate -Person $Person -MainMap $MainMap
    #>
    $Database = <REDACTED> # Database where Epic information lives
    $Table = <REDACTED> # Table containing subtemplate Epic info

    # Filter to match on job title and job role
    $Filter = <REDACTED>

    # Selected attributes from the SQL query
    $SelectedData = <REDACTED>

    # SQL query to get the Epic subtemplates of an account by job title and role
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Database  `
        -Query $Query 
    } # END try
    catch {
      # Exit the application if the query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-SubTemplate

  Function Get-Blueprints ($Person, $MainMap) {
    <#
      .DESCRIPTION
      Get the blueprints for the person via the previously created Main Map.

      .EXAMPLE
      Get-Blueprints -Person $Person -MainMap $MainMap
    #>
    $Database = <REDACTED> # Database containing Epic information
    $Table = <REDACTED> # Table with Epic Blueprint information

    # Filter based on job title and role
    $Filter = <REDACTED>

    # Selected attributes for the SQL query
    $SelectedData = <REDACTED>

    # SQL query to get the Epic Blueprints by filtering on job title and role
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Database  `
        -Query $Query 
    } # END try
    catch {
      # Exit the application if the query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      Exit
    } # END try catch
  } # END Get-Blueprints

  Function Get-TrainingTracks ($Person, $MainMap) {
    <#
      .DESCRIPTION
      Get the training tacks for the person via the Main Map.

      .EXAMPLE
      Get-TrainingTracks -Person $Person -MainMap $MainMap
    #>
    $Database = <REDACTED> # Database containing Epic information
    $Table = <REDACTED> # Table with Epic TrainingTrack information

    # Filter for the training tracks by the job category from Epic Map
    $Filter = <REDACTED>

    # Select all attributes
    $SelectedData = "*"

    # SQL query to get all training tracks based on Epic job category
    $Query = "Select $SelectedData from $Table where $Filter"

    try {
      # Attempt to run the SQL query
      Return Invoke-Sqlcmd -ServerInstance $Config.SqlServer -Database $Database  `
        -Query $Query 
    } # END try
    catch {
      # Exit the application if the query fails
      Write-Log -Level ERROR -Message "{0} :: Could not proccess SQL query. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name
      #Exit
    } # END try catch
  }

  Function Get-UserAccountInformation ($EmpID) {
    <#
      .DESCRIPTION
      This function is used to combine everything together and work with a singluar individual.
      Different parts of the user custom object get processed here.
      Information, not required, is commented out to prevent bad data.

      .EXAMPLE
      Get-UserAccountInformation <REDACTED>
    #>
    Write-Log "{0} :: Getting account information for {1}" -Arguments $($MyInvocation).MyCommand.Name, $EmpID

    try {
      # Attempt to create a person object
      $Person = Get-PersonByID <REDACTED> -Config $Config # Get UKG data
      $Person.<REDACTED> = Get-Username -Person $Person # Create the expected username
      $Person.<REDACTED> = Get-EmailAddress -Person $Person # Create the expected email address
      $EpicJobMap = Get-EpicJobMap -Person $Person # Attempt to grab the Epic job information
      $MainTemplate = Get-MainTemplate -Person $Person -MainMap $EpicJobMap # Attempt to get the Epic main templates
      $SubTemplate = Get-Subtemplate -Person $Person -MainMap $EpicJobMap # Attempt to get the Epic sub templates
      $Blueprint = Get-Blueprints -Person $Person -MainMap $EpicJobMap # Attempt to get the Epic blueprints
      $Training = Get-TrainingTracks -Person $Person -MainMap $EpicJobMap # Attempt to get the Epic Training Tracks
  
      $Person | Add-Member -Name "initialPassword"            -Type NoteProperty -Value (Get-Password) # Set the password
      $Person | Add-Member -Name "Initials"                   -Type NoteProperty -Value (Get-Initials -Person $Person) # set the initials
      $Person | Add-Member -Name "GUID"                       -Type NoteProperty -value "Unknown"
      $Person | Add-Member -Name "Job_Role"                   -Type NoteProperty -Value $EpicJobMap.<REDACTED>
      $Person | Add-Member -Name "Responsible_Application"    -Type NoteProperty -Value $EpicJobMap.<REDACTED>
      $Person | Add-Member -Name "Epic_Job_Category_1"        -Type NoteProperty -Value $EpicJobMap.<REDACTED>
      $Person | Add-Member -Name "Epic_JobMap"                -Type NoteProperty -Value $EpicJobMap
      $Person | Add-Member -Name "Template"                   -Type NoteProperty -Value $MainTemplate
      $Person | Add-Member -Name "Subtemplate"                -Type NoteProperty -Value $SubTemplate
      $Person | Add-Member -Name "Blueprint"                  -Type NoteProperty -Value $Blueprint
      $Person | Add-Member -Name "Training"                   -Type NoteProperty -Value $Training
  
      Write-Log "{0} :: Got account information for {1}" -Arguments $($MyInvocation).MyCommand.Name, <REDACTED>
      Return $Person
    } # END try
    catch {
      # Exit the application is object assignment fails
      Write-Log -Level ERROR -Message "{0} :: Could not create person object for {1}. Exiting for safety" -Arguments $($MyInvocation).MyCommand.Name, <REDACTED>
      Exit
    } # END try catch
  } # END Get-UserAccountInformation
} # END BEGIN

PROCESS {
  <#
    .DESCRIPTION
    Logic used to run the script.
    All actions occur here.
  #>

  # Log script execution time
  Write-Log "{0} :: Started script execution" -Arguments $($MyInvocation).MyCommand.Name

  # Rotate logs to not fill disk space
  Start-LogRotation -Path $ScriptLogs

  # Create creadentials for the service account
  if ($MakeCreds -eq $true) {
    # If script is set to create the password
    # Create the secure string if one does not exist
    $PassCheck = Test-Path "$ScriptPath\Secure_Pass.txt"
    if (!$PassCheck) {
      # If the password file does not exist
      New-SecureString -Output "$ScriptPath\Secure_Pass.txt"
    } # END if
  } # END if

  # Create PS Credentials for later in the script
  #####
  # Set name of service account here
  #####
  $Password = Read-SecureString -File "$ScriptPath\Secure_Pass.txt"
  $Credential = New-Credential -Username "<REDACTED>" -Password $Password

  # Configuration object to hold common data
  $Config = [PSCustomObject]@{
    SqlServer  = <REDACTED># SQL server to run all queries
    Database   = <REDACTED># Main databse for employee information
    Credential = $Credential # Credential to use with the script and run queries
    SmtpServer = <REDACTED> # SMTP location to send mail
    SmtpFrom   = <REDACTED> # Email address to send mail from
    Creds      = $Credential # Credentials used to run commands
  }
  Write-Log "{0} :: Created configuration object for script execution" -Arguments $($MyInvocation).MyCommand.Name

  # Creating Cache
  Get-Cache -ExpirationDays 2
  Write-Log "{0} :: Created cache object for script execution" -Arguments $($MyInvocation).MyCommand.Name

  # Array to hold the output information for the report
  $EpicList = @()
  $TrainingList = @()
  $UserList = @()
  $HRList = @()
  $ManagerList = @()

  # Manual script changes for getting a single person or many based on date/time
  #####
  # CONTROL LOCATION
  #####
  $AccountList = Get-LastCreated -Days 2 -Config $Config
  #$AccountList = Get-PersonByID <REDACTED> <REDACTED> -Config $Config

  # Main loop for get information from all accounts
  Foreach ($AccountID in $AccountList) {
    # For every account found in UKG databse
    Write-Log "{0} :: Checking cache for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
    $DetectCache = Select-String -Path $CacheFile -Pattern $AccountID.<REDACTED> # Check if that account is in the cache

    if ($DetectCache) {
      # If the account was in the cache
      Write-Log "{0} :: {1} was found in cache file, skipping" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
      Continue # Skip
    } # END if

    # Get the information about the account from the UKG database
    $Account = get-UserAccountInformation -EmpID $AccountID.<REDACTED>

    if ([string]::IsNullOrEmpty($Account.<REDACTED>)) {
      # If the account does not have middle name
      $MiddleName = "" # Blank out the middle name to remove bad characters
    } # END if
    else {
      # Otherwise set the middle name and remove any trailing spaces
      $MiddleName = ($Account.<REDACTED>).Trim() # Database data is dirty
    } # END if else

    # Create or use the organizational unit where the account will be housed
    $OU = Get-DepartmentOU -Department $Account.<REDACTED>

    # Make the user account in the OU defined above
    Write-Log "{0} :: Account {1} is attempting to be created" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
    New-AdAccount -Person $Account -Location $OU

    $GUID = Get-UserGUID -Person $Account.<REDACTED>

        
    # Create a object to contain employee information for the report export
    $UserTable = @(
      [ordered]@{
        #GUID            = $GUID.Guid
        EmpID           = $Account.<REDACTED>;
        Username        = $Account.<REDACTED>;
        FirstName       = $Account.<REDACTED>
        MiddleName      = $Middlename
        LastName        = $Account.<REDACTED>
        JobTitle        = $Account.<REDACTED>
        JobRole         = $Account.<REDACTED>
        Department      = $Account.<REDACTED>
        Supervisor      = $Account.<REDACTED>
        Active          = $Account.<REDACTED>
      }
    ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
    Write-Log "{0} :: Created output table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>

    # Filter for only accounts that are active and not terminated
    if ($UserTable.Active -eq "Active") {
      # If the account is listed as active
      $UserList += $UserTable # Add the account data to the user table report
    } # END if
    else {
      # Otherwise the account was terminated
      Write-Log "{0} :: Account {1} was terminated" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
    } # END if else

    # Create a object to contain employee information for the report export
    $ManagerTable = @(
      [ordered]@{
        #GUID            = $GUID.Guid
        EmpID           = $Account.<REDACTED>;
        Username        = $Account.<REDACTED>;
        InitialPassword = $Account.initialPassword
        FirstName       = $Account.<REDACTED>
        MiddleName      = $Middlename
        LastName        = $Account.<REDACTED>
        JobTitle        = $Account.<REDACTED>
        JobRole         = $Account.<REDACTED>
        Department      = $Account.<REDACTED>
        Supervisor      = $Account.<REDACTED>
        Active          = $Account.<REDACTED>
      }
    ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
    Write-Log "{0} :: Created output table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>

    # Filter for only accounts that are active and not terminated
    if ($ManagerTable.Active -eq "Active") {
      # If the account is listed as active
      $ManagerList += $ManagerTable # Add the account data to the user table report
    } # END if
    else {
      # Otherwise the account was terminated
      Write-Log "{0} :: Account {1} was terminated" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
    } # END if else

    $HRTable = @(
      [ordered]@{
        EmpID           = $Account.<REDACTED>;
        FirstName       = $Account.<REDACTED>
        MiddleName      = $Middlename
        LastName        = $Account.<REDACTED>
        MailStop        = $Account.<REDACTED>;
        Email           = $Account.<REDACTED>
        Active          = $Account.<REDACTED>
      }
    ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
    Write-Log "{0} :: Created output table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>

    # Filter for only accounts that are active and not terminated
    if ($HRTable.Active -eq "Active") {
      # If the account is listed as active
      $HRList += $HRTable # Add the account data to the user table report
    } # END if
    else {
      # Otherwise the account was terminated
      Write-Log "{0} :: Account {1} was terminated" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
    } # END if else

    # Process the tempaltes for the output report
    foreach ($Template in $Account.Template) {
      # For each template belonging to an account
      if ([string]::IsNullOrEmpty($Template.Template_ID)) {
        # IF the Template is null
        continue # Skip
      } # END if
      else {
        # Otherwise create the template report object
        $EpicTable = @(
          [ordered]@{
            GUID            = $GUID.guid
            EmpID           = $Account.<REDACTED>;
            Username        = $Account.<REDACTED>;
            FirstName       = $Account.<REDACTED>
            LastName        = $Account.<REDACTED>
            TemplateID      = $Template.Template_ID
            TemplateName    = $Template.Template_Name
            EMP             = $Template.EMP
            SER             = $Template.SER
            SubtemplateID   = ""
            SubtemplateName = ""
            BlueprintID     = ""
            BlueprintName   = ""
          }
        ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

        $EpicList += $EpicTable
        Write-Log "{0} :: Created tempate table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
      } # END if
    } # END foreach

    # Process the sub tempaltes for the output report
    foreach ($SubTemplate in $Account.Subtemplate) {
      # For each subtemplate in the account
      if ([string]::IsNullOrEmpty($SubTemplate.Subtemplate_ID)) {
        # If the subtemplate is empty
        continue # Skip
      } # END if
      else {
        # Otherwise create the subtempalte report object
        $EpicTable = @(
          [ordered]@{
            GUID            = $GUID.guid
            EmpID           = $Account.<REDACTED>;
            Username        = $Account.<REDACTED>;
            TemplateID      = ""
            TemplateName    = ""
            EMP             = ""
            SER             = ""
            SubtemplateID   = $SubTemplate.Subtemplate_ID
            SubtemplateName = $SubTemplate.Subtemplate_Name
            BlueprintID     = ""
            BlueprintName   = ""

          }
        ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

        $EpicList += $EpicTable
        Write-Log "{0} :: Created subtemplate table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
      } #END if
    } # END foreach 

    # Process the blueprints for the output report
    foreach ($Blueprint in $Account.Blueprint) {
      # For each blueprint in account
      if ([string]::IsNullOrEmpty($Blueprint.Blueprint_ID)) {
        # If the blueprint is empty
        continue # Skip
      } # END if
      else {
        # Otherwise create the blueprint report table
        $EpicTable = @(
          [ordered]@{
            GUID            = $GUID.guid
            EmpID           = $Account.<REDACTED>;
            Username        = $Account.<REDACTED>;
            TemplateID      = ""
            TemplateName    = ""
            EMP             = ""
            SER             = ""
            SubtemplateID   = ""
            SubtemplateName = ""
            BlueprintID     = $Blueprint.Blueprint_ID
            BlueprintName   = $Blueprint.Blueprint_Name
          } # END EpicTable
        ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

        $EpicList += $EpicTable
        Write-Log "{0} :: Created blueprint table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>
      } # END if
    } # END Foreach

    # Information table on what training is required by an account.
    $TrainingTable = @(
      [ordered]@{
        GUID         = $GUID.guid
        EmpID        = $Account.<REDACTED>;
        Username     = $Account.<REDACTED>;
        FirstName    = $Account.<REDACTED>;
        LastName     = $Account.<REDACTED>;
        JobCategory  = $Account.Training."Job Category Name"
        JobTitle     = $Account.<REDACTED>
        JobRole      = $Account.<REDACTED>
        Department   = $Account.<REDACTED>
        "Training 1" = $Account.Training.'Training Track 1'
        "Training 2" = $Account.Training.'Training Track 2'
        "Training 3" = $Account.Training.'Training Track 3'
        "Training 4" = $Acocunt.Training.'Training Track 4'
        "Training 5" = $Account.Training.'Training Track 5'
        "Training 6" = $Account.Training.'Training Track 6'
      } #END TrainingTable
    ) | ForEach-Object { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }

    $TrainingList += $TrainingTable
    Write-Log "{0} :: Created training table for {1}" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>

    Write-Log "{0} :: Appending {1} to cache" -Arguments $($MyInvocation).MyCommand.Name, $AccountID.<REDACTED>

    $CacheID = $AccountID.<REDACTED> # Get the employee ID to add to cache
    Add-Content -Path $CacheFile -Value "$CacheID" # Add that ID to the cache file
  } # END foreach MAIN
} # END PROCESS

END {
  <#
    .DESCRIPTION
    This section is used to generate reports, email stakeholders, and to perform any ending tasks
  #>

  # Create objects to add to the email reports
  $UserList | Format-Table
  $EpicList | Format-Table
  $HRList   | Format-Table

  # Send the employee information
  # Take from email chain
  $MessageBody = Get-MailBody -Data $UserList -ReportName "New Education / UKG User Report" -Description "New person added to the HR UKG system. Used for Education."
  Get-MailTemplate -Config $Config -Subject "UKG User Report" -Body $MessageBody -To <REDACTED>

  # Send the employee information
  $MessageBody = Get-MailBody -Data $HRList -ReportName "New HR / UKG User Report" -Description "New person added to the HR UKG system. Used to make new AD accounts."
  Get-MailTemplate -Config $Config -Subject "UKG User Report" -Body $MessageBody -To <REDACTED>

  # Send the Epic template information
  $MessageBody = Get-MailBody -Data $EpicList -ReportName "Epic Template Report" -Description "New person added to the HR UKG system with Epic Access Templates."
  Get-MailTemplate -Config $Config -Subject "UKG User Report" -Body $MessageBody -To <REDACTED>

  # Send Training Track information
  $MessageBody = Get-MailBody -Data $TrainingList -ReportName "Epic Training Report" -Description "New person who requires Epic training."
  Get-MailTemplate -Config $Config -Subject "UKG User Report" -Body $MessageBody -To <REDACTED>

  Write-Log "{0} :: Stopped script execution" -Arguments $MyInvocation.MyCommand.Name
  Exit
} # END END
