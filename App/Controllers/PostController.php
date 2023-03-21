<?php

/*   Copyright 2023 Plancksoft

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.*/

	class PostController {
		
		protected $Client;
		protected $PostsCollection;
		
		protected $Token = "";
		protected $TokenData = [];
		
		public function __construct($InputData, $ActionMethod, $Client, $IP = false, $PUBLIC_RSA_KEY = "")
		{
			if (isset($InputData["Action"]) && $InputData["Action"] !== "")
			{
				if ($IP !== false)
				{
					$this->IP = $IP;
				} else {
					Logger::Log(Settings::$LogPrefix, "has refused the connection due to a failure in acquiring IP Address");
				
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to a failure in acquiring IP Address."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
					}
				if (isset($InputData["Token"]) && $InputData["Token"] !== "")
				{
					if ($ActionMethod !== "")
					{
						$this->Client = $Client;
						$this->PostsCollection = $this->Client->ScholarFindr->Posts;
						
						$this->Token = $InputData["Token"];
						$this->TokenData = Token::Decode($this->Token);
					}
				} else {
					return false;
				}
			} else {
				Logger::Log(Settings::$LogPrefix, "has refused the connection due to an invalid supplied Action");
				
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => Settings::$LogPrefix . " has refused the connection due to an invalid supplied Action."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
		
		public function __destruct() {
			// Destroying class.
		}
		
		function FetchPostsAction($PUBLIC_RSA_KEY = "")
		{
			$Filter = ["uid" => $this->TokenData["user"]["uid"]];
			$Options = ['sort' => ['timestamp' => -1], 'limit' => 100];
			$PostsInfo = $this->PostsCollection->find($Filter, $Options);
			
			if (isset($PostsInfo) && $PostsInfo !== null)
			{
				$FoundPost = false;
				$PostsList = [];
				
				foreach($PostsInfo as $Post)
				{
					if ($Post->uid === $this->TokenData["user"]["uid"])
					{
						$FoundPost = true;
						array_push($PostsList, $Post);
					} else {
						$FoundPost = false;
					}
				}
				if ($FoundPost)
				{
					$RenewedToken = Token::Generate($this->TokenData["user"]["uid"], "", $this->Token, $this->TokenData["sequence"], $PUBLIC_RSA_KEY);
					
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 1, "message" => $PostsList, "token" => $RenewedToken], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				} else if (!$FoundPost)
				{
					$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "No Posts were found according to your provided filters."], true)), $PUBLIC_RSA_KEY);
					$ResponseSignature = Security::SignMessage($EncryptedResponse);
					
					return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
				}
			} else {
				$EncryptedResponse = Security::Encrypt(base64_encode(json_encode(["status" => 0, "message" => "No Posts were found according to your provided filters."], true)), $PUBLIC_RSA_KEY);
				$ResponseSignature = Security::SignMessage($EncryptedResponse);
				
				return json_encode(["response" => $EncryptedResponse, "signature" => $ResponseSignature], true);
			}
		}
	}
?>