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

class Token
{
    private $client;

    public function __construct($client)
    {
        $this->client = $client;
    }

    public function validate($token = "", $publicKey = "")
    {
        if (empty($token)) {
            throw new Exception("API Token must be supplied.");
        }

        $decodedToken = $this->decodeToken($token);

        if (empty($decodedToken["timestamp"])) {
            throw new Exception("An invalid API Token was supplied.");
        }

        $tokenDate = date($decodedToken["timestamp"]);
        $validTimeRange = new DateTime("-8 minutes");
        $validTimeRange = $validTimeRange->format("d/m/Y H:i:s");

        if ($tokenDate < $validTimeRange) {
            throw new Exception("Supplied API Token has expired, and/or could be invalid.");
        }

        $uid = $decodedToken["user"]["uid"] ?? null;

        if (empty($uid)) {
            throw new Exception("Your supplied API Token is invalid.");
        }

        $authInfo = $this->client->selectCollection("ScholarFindr", "Auth")->findOne([
            "token" => $token,
            "uid" => $uid,
            "ipv4" => $decodedToken["ipv4"]
        ]);

        if (!$authInfo) {
            throw new Exception("Your supplied API Token is invalid.");
        }

        return $authInfo->token;
    }

    private function decodeToken($token)
    {
        return json_decode(base64_decode($token), true);
    }
}

?>
