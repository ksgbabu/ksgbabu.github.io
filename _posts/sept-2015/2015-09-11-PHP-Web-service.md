---
layout: post
---

Example for a PHP web service consumption is depicted below:

	<?php
	
	$soapReqBody = <<<EOD
	<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
	 <s:Header>
	  <ActivityId CorrelationId="4633af8b-873d-4be7-9acd-987589448fd9" xmlns="http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics">
	                    6cf7c607-8e65-44eb-820d-66f809fe387b</ActivityId>
	 </s:Header>
	 <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	  <EVRN_UnitSearchRQ EchoToken="Blah" Version="1.0" Target="Test" ResponseType="PropertyList" xmlns="http://www.xxpia.com/EVRN/2007/02">
	   <POS>
	    <Source>
	     <RequestorID ID="DemoPartner" MessagePassword="mypp"/>
	    </Source>
	   </POS>
	   <Criteria AvailableOnlyIndicator="false">
	    <Criterion>
	     <Address>
	      <CountryName Code="US"/>
	     </Address>
	     <UnitStayCandidate/>
	    </Criterion>
	   </Criteria>
	  </EVRN_UnitSearchRQ>
	 </s:Body>
	</s:Envelope>
	EOD;
	$url = "https://api.xpia.com/EVRNService.svc";
	
	$responseData = doCURLRequest($method = "POST", 'beta.xpia.com', $url, $soapReqBody, 'UnitSearch');
	//die($responseData);
	$doc = simplexml_load_string($responseData);
	$arr_unitcode = array();
	$i = 0;
	foreach ($doc->xpath('//s:Body') as $header) {
	    foreach ($header->EVRN_UnitSearchRS->Units->Unit as $field) {
	        $arr_unicode[$i]['unitcode'] = $field->attributes()->UnitCode . '<br />';
	        $arr_UnitName[$i]['UnitName='] = $field->attributes()->UnitName . '<br />';
	        $arr_InfoSource[$i]['InfoSource'] = $field->attributes()->InfoSource . '<br />';
	        $arr_UnitHeadline[$i]['UnitHeadline'] = $field->attributes()->UnitHeadline . '<br />';
	        $arr_UnitClassCode[$i]['UnitClassCode'] = $field->attributes()->UnitClassCode . '<br />';
	        $i++;
	    }
	}
	
	var_dump($arr_UnitClassCode);
	
	function doCURLRequest($method = "POST", $host, $url, $soapReqBody, $soapAction) {
	    $headers = array(
	        'Content-Type: text/xml; charset=utf-8',
	        'Content-Length: ' . strlen($soapReqBody),
	        'Accept: text/xml',
	        'Cache-Control: no-cache',
	        'Pragma: no-cache',
	        'VsDebuggerCausalityData: uIDPo0iJ7VJ2NGFBgys4y9GtaGMAAAAAiMHjziQul0yXkpCjyYkJAXddB66L5QdDnGSQ/3AWJyoACQAA',
	        'SOAPAction: "' . $soapAction . '"',
	        "Host: $host",
	        "Expect: 100-continue"
	    );
	    $ch = curl_init();
	    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	    curl_setopt($ch, CURLOPT_URL, $url);
	    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
	    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	    //curl_setopt($ch, CURLOPT_USERAGENT, $defined_vars['HTTP_USER_AGENT']);
	    curl_setopt($ch, CURLOPT_POST, true);
	    curl_setopt($ch, CURLOPT_POSTFIELDS, $soapReqBody);
	    //curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	    //curl_setopt($ch, CURLOPT_USERPWD, $credentials);
	    $response = curl_exec($ch);
	    return $response;
	}
	
	?>
