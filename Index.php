<?php
	// Import all custom classes here
	
	require_once('Classes/Security.php');
	require_once('Classes/SCrypt.php');
	include_once("Classes/Token.php");
	include_once("Classes/Logger.php");
	require_once("Controllers/AuthenticationController.php");
	require_once('vendor/autoload.php');

	if(!empty($_SERVER['REMOTE_ADDR']))
	{
		$IP = $_SERVER['REMOTE_ADDR'];
	
		if ($IP !== "localhost" || $IP !== "127.0.0.1") // Development IP Address for error logging capabilities. (re-work this part in a master configuration file.)
		{
			error_reporting(0);
		} else {
			error_reporting(E_ALL);
		}
	}
	
	
	$RequestedAction = "";
	$InputData = json_decode(json_encode(["InputData" => array()], true), true);
	$_REQUEST = json_decode(file_get_contents('php://input'), true);
	
	$PUBLIC_RSA_KEY = "";
	
	$Signature = $_REQUEST["Signature"];
	$InputData = $_REQUEST["InputData"];
	
	if (isset($_REQUEST["PUBLIC_RSA_KEY"]))
	{
		$PUBLIC_RSA_KEY = base64_decode($_REQUEST["PUBLIC_RSA_KEY"]);
		if ($PUBLIC_RSA_KEY == "")
		{
			echo json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a missing public RSA key."], true);
			Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a missing public RSA key");
			die();
		}
	} else {
		echo json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a missing public RSA key."], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a missing public RSA key");
		die();
	}
	
	if ((strpos($PUBLIC_RSA_KEY, "BEGIN RSA PUBLIC KEY") !== false))
	{
		$tempPUBLIC_RSA_KEY = str_replace('-----BEGIN RSA PUBLIC KEY-----', '', $PUBLIC_RSA_KEY);
		$tempPUBLIC_RSA_KEY = trim(str_replace('-----END RSA PUBLIC KEY-----', '', $tempPUBLIC_RSA_KEY));
		$PUBLIC_RSA_KEY = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A' . str_replace("\n", '', $tempPUBLIC_RSA_KEY);
		$PUBLIC_RSA_KEY = "-----BEGIN PUBLIC KEY-----\n" . wordwrap($PUBLIC_RSA_KEY, 64, "\n", true) . "\n-----END PUBLIC KEY-----";
	}
	
	if (!Security::VerifyMessage($InputData, $Signature, $PUBLIC_RSA_KEY))
	{
		echo json_encode(["response" => Settings::$LogPrefix . " has refused the connection due to an invalid request signature."], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to an invalid request signature");
		die();
	} else {
		$InputData = json_decode(Security::Decrypt($InputData), true);
	}
	
	if (isset($InputData))
	{
		$InputData = Security::Secure($InputData, $PUBLIC_RSA_KEY);
		if (!$InputData)
		{
			$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection as it was unable to secure input data."], true)), $PUBLIC_RSA_KEY);
			$ResponseSignature = Security::SignMessage($EncryptedResponse);
			
			echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " as it was unable to secure input data");
			die();
		} else {
			Security::BlockInvalidTraffic($InputData, $PUBLIC_RSA_KEY);
		}
	}
	
	if (isset($InputData["Action"]))
	{
		if ($InputData["Action"] !== null)
		{
			$RequestedAction = htmlspecialchars(strip_tags($InputData["Action"]));
		} else {
			$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a missing action parameter."], true)), $PUBLIC_RSA_KEY);
			$ResponseSignature = Security::SignMessage($EncryptedResponse);
			
			echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a missing action parameter");
			die();
		}
	} else {
		$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a missing action parameter."], true)), $PUBLIC_RSA_KEY);
		$ResponseSignature = Security::SignMessage($EncryptedResponse);
		
		echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a missing action parameter");
		die();
	}
	
	$Actions = file_get_contents("Actions.json");
	if ($Actions === false) {
		$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a misconfiguration in the Actions configuration file."], true)), $PUBLIC_RSA_KEY);
		$ResponseSignature = Security::SignMessage($EncryptedResponse);
		
		echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a misconfiguration in the Actions configuration file");
		die();
	}

	$Actions = json_decode($Actions, true);
	if ($Actions === null) {
		$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a misconfiguration in the Actions configuration file."], true)), $PUBLIC_RSA_KEY);
		$ResponseSignature = Security::SignMessage($EncryptedResponse);
		
		echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a misconfiguration in the Actions configuration file");
		die();
	}
	
	$ActionController = "";
	$ActionMethod = "";
	
	foreach($Actions as $Action) {
		$ActionInformation = $Action["0"];
		
		if($RequestedAction === $ActionInformation["Action"]) {
			$ActionController = $ActionInformation["Controller"];
			$ActionMethod = $ActionInformation["Method"];
			$ActionToken = $ActionInformation["TokenRequired"];
			$ActionMaintenance = $ActionInformation["Maintenance"];
			
			if ($ActionToken === 1)
			{
				if (!isset($InputData["Token"]) || $InputData["Token"] === "")
				{
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a missing mandatory token."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a missing mandatory token");
					die();
				} else {
					if (!$InputData["Token"] = Token::Validate($InputData["Token"], $PUBLIC_RSA_KEY)){
						Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a failure validating the token");
						die();
					}
				}
			} else if ($ActionToken === 2){
				if (isset($InputData["Token"]))
				{
					if (!Token::Decode(Token::Validate($InputData["Token"], $PUBLIC_RSA_KEY))){
						Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a failure validating the token");
						die();
					}
				}
			}
			
			if ($ActionMaintenance === 1)
			{
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => -1, "message" => Settings::$LogPrefix . " has refused the connection due to requested API {$RequestedAction} being under maintenance."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to requested API {$RequestedAction} being under maintenance");
				die();
			}
		}
	}
	
	if ($ActionController === "")
	{
		$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to an invalid supplied Action."], true)), $PUBLIC_RSA_KEY);
		$ResponseSignature = Security::SignMessage($EncryptedResponse);
		
		echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
		Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to an invalid supplied Action");
		die();
	} else {
		try{
			$ActionControllerPath = "Controllers\\" . $ActionController . ".php";
			require_once($ActionControllerPath);
			
			if ($ActionMethod !== "")
			{
				$Action = new $ActionController($InputData, $ActionMethod, new MongoDB\Client, $IP, $PUBLIC_RSA_KEY);
				$Response = $Action->$ActionMethod($PUBLIC_RSA_KEY);
				
				if (isset($Response))
				{
					echo $Response;
					die();
				} else {
					Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " as it was unable to successfully perform requested action");
					
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " was unable to successfully perform requested action."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					die();
				}
			}
			else {
				Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " due to a misconfiguration in the Actions configuration file");
				
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a misconfiguration in the Actions configuration file."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				die();
			}
		} catch (Exception $Exception)
		{
			Logger::Log(Settings::$LogPrefix, "has refused a connection from IP: " . $IP . " as it was unable to successfully perform requested action");
			
			$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " was unable to successfully perform requested action."], true)), $PUBLIC_RSA_KEY);
			$ResponseSignature = Security::SignMessage($EncryptedResponse);
			
			echo json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			
			die();
		}
	}
?>