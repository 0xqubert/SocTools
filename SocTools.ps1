<#Requires -RunAsAdministrator#>
# Set the log file path
$logFile = "logs\SocTools.log"  #Change this to your desired log path
$delimiter = "__END_OF_RESPONSE__"
$computerList = @(
            "DESKTOP-JUJ4D1S"
            #"computer2",
            #"computer3"
            # Add more computer names as needed
        )

# Function to write to log
function LogWrite([string]$logMessage)
{
    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
     try {
        Add-Content -Path $logFile -Value "$currentTime - SocTools.ps1: $logMessage" -ErrorAction Stop
    }
    catch {
        Write-Host "Error writing to log file $($logFile): $($_.Exception.Message)"
    }
}

# Function to handle errors consistently
function Write-ErrorResponse {
    param (
        [string]$FunctionName,
        [System.Exception]$Exception
    )
    $errorMessage = "Error in $FunctionName :" + $($Exception.Message)
    LogWrite -logMessage $errorMessage
    return @{
        Success = $false
        Error = $errorMessage
    }
}

# Define a custom class to maintain property order
class ResponseObject {
    [string]$action
    [bool]$success
    [object]$output
}

# Function to display formatted table output
function Format-TableOutput {
    param (
        [object]$Data
    )
    if ($Data) {
        $output = $Data | Format-Table -AutoSize | Out-String
        LogWrite -logMessage "Formatted Table Output: $($output)"
        $output
    } else {
        $noDataMessage = "No data to display."
        LogWrite -logMessage $noDataMessage
        $noDataMessage
    }
}

# Function to display formatted list output
function Format-ListOutput {
     param (
        [object]$Data
    )
    if ($Data) {
        $output = $Data | Format-List | Out-String
        LogWrite -logMessage "Formatted List Output: $($output)"
        $output
    } else {
        $noDataMessage = "No data to display."
        LogWrite -logMessage $noDataMessage
        $noDataMessage
    }
}

# Function to split user input by newlines
function Split-UserInput {
    param (
        [string]$Input
    )
    if (-not [string]::IsNullOrEmpty($Input)) {
        return $Input -split '\n'
    } else {
        return @()
    }
}

function keepalive($result){
    try{
        $response = [ResponseObject]::new()
        $response.action = "keepalive"
        $response.success = $true
        return $response | ConvertTo-Json
    }
	catch{
		return Write-ErrorResponse -FunctionName "keepalive" -Exception $_.Exception
	}
}

function GetSocPcInfo($result){
    try{

        $softwareResultsList = @{}


        # Iterate through each computer in the list
        foreach ($computer in $computerList) {
            LogWrite("Starting processing for computer: $computer")

            # Check if the computer is reachable
            #$pingResult = Test-Connection -ComputerName $computer -Quiet
            if ($true) {
                LogWrite("Computer $computer is reachable.")
                try {
                    # --- Gather System Information ---
                    LogWrite "Gathering system information..."
                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer -ErrorAction Stop
                    if ($computerSystem) {
                        $model = $($computerSystem.Model)
                        $manufacturer = $($computerSystem.Manufacturer)
                        $memory = $([math]::Round(($computerSystem.TotalPhysicalMemory / 1GB), 2))
                        $computerName = $($computerSystem.Name)
                        if($computerSystem.UserName){
                            $loggedInUser = $($computerSystem.UserName)
                            $currentuser = ($loggedInUser -split '\\')[-1]
                        }
                        else{
                            LogWrite "   No logged in user."
                        }
                    } else {
                        LogWrite "   Error: Could not retrieve Win32_ComputerSystem data."
                    }

                    # --- Gather Disk Space Information ---
                    LogWrite "Gathering disk space information..."
                    $diskDrives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $computer -ErrorAction Stop
                    if($diskDrives){
                       foreach ($disk in $diskDrives) {
                            $drive = "$($disk.DeviceID) $($disk.VolumeName)"
                            $driveSize = $([math]::Round(($disk.Size / 1GB), 2))
                            $freeSpace = $([math]::Round(($disk.FreeSpace / 1GB), 2))
                        }
                    } else {
                        LogWrite "   Error: Could not retrieve Win32_LogicalDisk data."
                    }
                    # --- Gather Installed Software Information ---
                    LogWrite "Gathering installed software information..."
                    $softwareList = @("Visual Studio Code", "Crowdstrike", "Zscaler")
                    try{
                        foreach($item in $softwareList){
                            $softwareInfo = Get-Package | Where-Object {$_.Name -like "*$item*"}  | Select-Object Name, Version
                            if($softwareInfo)
                            {
                                $softwareResultsList[($item)] = "$($softwareInfo.Name) - Version: $($softwareInfo.Version)"
                            }
                            else
                            {
                                LogWrite "   No software matching name `"$item`" was found."
                            }
                        }
                    }
                     catch {
                        LogWrite "   Error retrieving installed software information: $($_.Exception.Message)"
                    }
                    try{
                        $lastreboot = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName . ).LastBootUpTime)
                    }catch {
                        LogWrite "   Error retrieving last reboot time: $($_.Exception.Message)"
                    }

                    LogWrite "Finished gathering information for $computer."

                }
                catch {
                    LogWrite "Error retrieving data for $computer : $($_.Exception.Message)"

                }
            } else {
                LogWrite "Computer $computer is unreachable."
            }
        }
        LogWrite "Script execution completed."
        $output = @{
            "computername" =  $computerName
            "currentuser" =  $currentuser
            "manufacturer" =  $manufacturer
            "lastreboot" = $lastreboot
            "pingresult" = $pingResult
            "drivesize" =  $driveSize
            "freespace" =  $freeSpace
            "memory" =  $memory
            "drive" =  $drive
            "model" = $model
            "os" =  $os
            "forcepoint" = $forcepoint
            "zscaler" = $zscaler
            "crowdstrike" = $crowdstrike
            "ciscoanyconnect" = $ciscoanyconnect
            "visualstudio" = $($softwareResultsList["Visual Studio Code"])
        }
        $response = [ResponseObject]::new()
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $output
        return $response | ConvertTo-Json
    }
    catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
    }

}

function GetCurrentUserInfo($result){
    try{
        $tableSubstring = (query user)[0] -split '\s+'
        $tableHeaders = '         '   
        $tableHeaders += $tableSubstring[1] + '                                       ' + $tableSubstring[2] + '         ' + $tableSubstring[3] + ' ' + $tableSubstring[4] + '       ' + $tableSubstring[5] + '   ' + $tableSubstring[6]
        $fullstring = ""
        foreach ($computer in $computerList) {
            LogWrite("Getting logged in user for computer: $computer")
            if (!(Test-Connection $computer -Count 1 -Quiet)){
                    write-host $computer "Offline" -ForegroundColor Red
            }
            else{
                $userTable = (query user /server:$computer 2>$null)
                $string = $computer
                $username = ""
                Foreach($o in $userTable){
                    if($o -match 'Active'){
                        #This is just to make the formatting look good for long names. Its ugly, dont look at it
                        $Parsed_Server = $o -split '\s+'
                        $Parsed_Server[2] = $Parsed_Server[2].PadRight(19)
                        $Parsed_Server[3] = $Parsed_Server[3].PadRight(2)
                        $Parsed_Server[4] = $Parsed_Server[4].PadRight(11)
                        $Parsed_Server[5] = $Parsed_Server[5].PadRight(6)
                        #Okay you can look again
                        $string += $Parsed_Server
                        #$username = net user /domain $Parsed_Server[1]
                        #$username = $username[3].Substring(9).Trim().PadRight(38)
                        #$userID = ($o -split "\s+")[1]
                        break
                    }                               
                }
                if($null -ne $userID){
                    $string.Replace($userID, "(" + $userID + ") " + $username)
                }else{
                    $fullstring += $string
                }
            }
        }
        LogWrite "Script execution completed."
        $fullstring = $fullstring -split '\s+'
        $output = @{
            "table" =  $fullstring
        }
        $response = [ResponseObject]::new()
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $output
        return $response | ConvertTo-Json
    }catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
    }
}

function ConnectRdp($result){
    $system = $result.input
    try{
        Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:$system"
        $output = @{
            "message" =  "Started new rpd process"
        }
        $response = [ResponseObject]::new()
        $response.action = $($MyInvocation.MyCommand.Name)
        $response.success = $true
        $response.output = $output
        return $response | ConvertTo-Json
    }catch{
        return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
    }
}

function RevokeMessage($userInput){
    LogWrite -logMessage "Starting RevokeMessage function."
    try{
       $MessageIDs = Split-UserInput -Input $userInput
       if($MessageIDs){
            $output = ""
            foreach ($ID in $MessageIDs)
            {
               $output += Format-TableOutput (Get-OMEMessageStatus -MessageId $ID | Select-Object Subject, IsRevocable, Revoked)
            }
            return @{
                Success = $true
                Output = $output
            }
       }
       else{
            $noMessageId = "No Message ID's provided"
            LogWrite -logMessage $noMessageId
            return @{
                Success = $false
                Error = $noMessageId
            }
       }
	}
	catch{
		return Write-ErrorResponse -FunctionName $($MyInvocation.MyCommand.Name) -Exception $_.Exception
	}
}

function SetSearchName($searchName){
    LogWrite -logMessage "Starting SetSearchName function."
	try{
		$searchData = Get-ComplianceSearch -Identity $searchName -ErrorAction Stop
        $output =  Format-ListOutput $searchData
        return @{
            Success = $true
            Output = $output
        }
	}
	catch{
        return Write-ErrorResponse -FunctionName "SetSearchName" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished SetSearchName function."
}


function PerformHardDelete($searchName){
    LogWrite -logMessage "Starting PerformHardDelete function."
    try{
        $output = New-ComplianceSearchAction -SearchName '$searchName' -Purge -PurgeType HardDelete | Format-Table
        #$output = whoami
        return @{
            Success = $true
            Output = $output
        }
    }
	catch{
		return Write-ErrorResponse -FunctionName "PerformHardDelete" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished PerformHardDelete function."
}

function UpdatePurgeStatus($searchName, $purgeString){
    LogWrite -logMessage "Starting UpdatePurgeStatus function."
	try{
        $purgeStatusData = (Get-ComplianceSearchAction -Identity "$searchName$purgeString" | Format-List -Property SearchName, Action, RunBy, JobStartTime, JobEndTime, Status, Errors | out-string)
        return @{
            Success = $true
            Output = $purgeStatusData
        }
    }
	catch{
		return Write-ErrorResponse -FunctionName "UpdatePurgeStatus" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished UpdatePurgeStatus function."
}

function CheckRevokeStatus($userInput){
    LogWrite -logMessage "Starting CheckRevokeStatus function."
	try{
		$MessageIDs = Split-UserInput -Input $userInput
        $output = ""
        if($MessageIDs){
            foreach ($ID in $MessageIDs)
            {
                $output += Format-TableOutput (Get-OMEMessageStatus -MessageId $ID | Select-Object Subject, IsRevocable, Revoked)
            }
            return @{
                Success = $true
                Output = $output
            }
        }
        else{
            $noMessageId = "No Message ID's provided"
            LogWrite -logMessage $noMessageId
            return @{
                Success = $false
                Error = $noMessageId
            }
        }
	}catch{
		return Write-ErrorResponse -FunctionName "CheckRevokeStatus" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished CheckRevokeStatus function."
}

function SetTimeRange(){
    LogWrite -logMessage "Starting SetTimeRange function."
	try{
	   #Logic for SetTimeRange here
		#Throw "Simulated Error in SetTimeRange"
        return @{
            Success = $true
            Output = "Set Time Range Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName "SetTimeRange" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished SetTimeRange function."
}

function SetUser(){
    LogWrite -logMessage "Starting SetUser function."
	try{
	   #Logic for SetUser here
		#Throw "Simulated Error in SetUser"
        return @{
            Success = $true
            Output = "Set User Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName "SetUser" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished SetUser function."
}
function SetOperations(){
    LogWrite -logMessage "Starting SetOperations function."
	try{
	   #Logic for SetOperations here
		#Throw "Simulated Error in SetOperations"
        return @{
            Success = $true
            Output = "Set Operations Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName "SetOperations" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished SetOperations function."
}
function SetMessageID(){
    LogWrite -logMessage "Starting SetMessageID function."
	try{
	   #Logic for SetMessageID here
		#Throw "Simulated Error in SetMessageID"
        return @{
            Success = $true
            Output = "Set Message ID Logic Ran."
        }
	}
	catch{
		return Write-ErrorResponse -FunctionName "SetMessageID" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished SetMessageID function."
}
function SEARCH(){
    LogWrite -logMessage "Starting SEARCH function."
		try{
	   #Logic for SEARCH here
		#Throw "Simulated Error in SEARCH"
        return @{
            Success = $true
            Output = "Search Logic Ran."
        }
		}
		catch{
			return Write-ErrorResponse -FunctionName "SEARCH" -Exception $_.Exception
		}
    LogWrite -logMessage "Finished SEARCH function."
}
function ClearResults(){
    LogWrite -logMessage "Starting ClearResults function."
	try{
        return @{
            Success = $true
            Output = "ClearResults"
        }
	}
	catch{
        return Write-ErrorResponse -FunctionName "SetSearchName" -Exception $_.Exception
	}
    LogWrite -logMessage "Finished ClearResults function."
}

# Function to Launch app.py
function Start-AppPy {

    # Start app.py with named pipe argument
    $process = Start-Process -FilePath "python3" -ArgumentList "app.py" -PassThru

    # Return information about the process
    return @{
        Process = $process
    }
}

$hostname = '127.0.0.1'
$port = 65432
$delimiter = "__END_OF_RESPONSE__"

# Define $appProcess in script scope
$appProcess = $null

function main(){
     # Start app.py and get the pipe information
     Write-Host "-------------------------------------------------------------"
     Write-Host "------------------- SocTools Initializing -------------------"
     Write-Host "-------------------------------------------------------------"
    LogWrite -logMessage "-------------------------------------------------------------"
    LogWrite -logMessage "------------------- SocTools Initializing -------------------"
    LogWrite -logMessage "-------------------------------------------------------------"

    $appInfo = Start-AppPy
    $appProcess = $appInfo.Process # Assign the value here in the script
    Write-Host "SocTools.ps1 started. Process ID: $($PID)"
    Write-Host "app.py started. Process ID: $($appProcess.Id)"
    LogWrite -logMessage "SocTools.ps1 started. Process ID: $($PID)"
    LogWrite -logMessage "app.py started. Process ID: $($appProcess.Id)"

    # Using .NET classes for sockets
    $server_socket = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($hostname), $PORT)
    $server_socket.Start()

    Write-Host "Listening on $($hostname):$($PORT)"
    LogWrite "Listening on $($hostname):$($PORT)"

    # Set up event to signal socket is up
    $tcp_ready = New-Object System.Threading.ManualResetEvent($false)
    $tcp_ready.Set() | Out-Null

    # Accept a client connection
    $client_socket = $server_socket.AcceptTcpClient()
    $client_addr = $client_socket.Client.RemoteEndPoint
    Write-Host "Accepted TCP connection from $($client_addr)"
    LogWrite "Accepted TCP connection from $($client_addr)"
    Write-Host "Connection Established!"
    Write-Host "SocTools.ps1($($hostname):$($PORT)) <---> app.py($($client_addr))"
    LogWrite -logMessage "Connection Established!"
    LogWrite -logMessage "SocTools.ps1($($hostname):$($PORT)) <---> app.py($($client_addr))"
    Write-Host "-------------------------------------------------------------"
    Write-Host "------- SocTools is running at http://127.0.0.1:5000 --------"
    Write-Host "-------------------------------------------------------------"
    LogWrite -logMessage "-------------------------------------------------------------"
    LogWrite -logMessage "------- SocTools is running at http://127.0.0.1:5000 --------"
    LogWrite -logMessage "-------------------------------------------------------------"

    try{
        # Handle the connection in this block.
        $stream = $client_socket.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)

        while ($client_socket.Connected)
        {
            if($stream.DataAvailable)
            {
                $command = $reader.ReadLine();
                LogWrite "Command received: $command";
                # Handle Command and Return Result
                $result = try{
                    $command | ConvertFrom-Json
                } catch {
                    @{
                        "error" = "Error parsing JSON";
                        "success" = $false
                    }
                }
                if ($result) {
                    $action = $result.action
                    if($action){
                        $response = try {
                            &$action($result)
                        } catch {
                            $response = @{
                                "error" = "Error executing command: $($_.Exception.Message)";
                                "success" = $false;
                                "action" = $action
                            } | ConvertTo-Json
                            LogWrite -logMessage "Error response generated: $($response)"; # Log the error response
                        }
                        $writer.WriteLine($response + $delimiter)
                        $writer.Flush()
                    }
                    else {
                        $response = @{
                            "error" = "No action received";
                            "success" = $false;
                        } | ConvertTo-Json
                        $writer.WriteLine($response + $delimiter)
                        $writer.Flush()
                    }
                }
                else {
                    $response = @{
                        "error" = "No command received";
                        "success" = $false;
                    } | ConvertTo-Json
                    $writer.WriteLine($response + $delimiter)
                    $writer.Flush()
                }
            }else{
                Start-Sleep -Milliseconds 100 # Check if data is available 10x a second
            }
        }
    }
    catch{
        LogWrite "Exception occurred: $($_.Exception.Message)"
    }
    finally
    {
        # Clean Up Connection
        $reader.Close()
        $writer.Close()
        $client_socket.Close();
        $server_socket.Stop();
        LogWrite "TCP connection from $($client_addr) closed."
        if ($appProcess) {
            LogWrite -logMessage "Terminating app.py"
            $appProcess | Stop-Process
        }
    }
}

main