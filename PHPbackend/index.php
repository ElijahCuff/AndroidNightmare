<?php
header('Content-Type: application/json');

// input parameters
$TxID = urlDecode($_GET['txid']);
$satoshiAmount = $_GET['amount'];
$addressOfReceiver = urlDecode($_GET['receiver']);
$testing = ($_GET['testing'] == "true");
$verifyAmount = ($_GET['verifyAmount'] == "true");
$verifyReceiver = ($_GET['verifyReceiver'] == "true");
$date = date('d-M-Y');
$log = "transaction.history";

// stop reusing txid's
function alreadyConfirmed($txid, $log)
{
       $transactions = file($log);
       $newTransaction = true;
       $found = false;
       foreach($transactions as $transaction){
            if(trim($transaction) == trim($txid)){
                 $found = true;
                }
              }
      return $found;
} 

function addVerified($txid, $log)
{
  file_put_contents($log,$txid.PHP_EOL, FILE_APPEND);
}



// Check Transaction
if(!$testing)
{
   if (!$TxID){
    header('HTTP/1.1 300 Missing TxID');
    exit("Missing Transaction ID");
    }
   
   if (alreadyConfirmed($TxID,$log)){
     header('HTTP/1.1 307 Transaction already verified');
     exit("The TxID provided has already been verified.");
    }

   if ($verifyReceiver){
    if(!$addressOfReceiver){
    header('HTTP/1.1 301 Missing Receiver Address');
    exit("Missing Address to Verify Received Amount");
     }
    }
if ($verifyAmount){
    if (!$satoshiAmount){
    header('HTTP/1.1 302 Missing Amount');
    exit("Missing Amount to Verify");
     }
    }

$confirms = checkTransfer($TxID,$addressOfReceiver,$satoshiAmount);
}
else
{
$confirms = checkTransfer();
}

// Start
if($confirms > 0)
{
   if($confirms <= 5)
   {
   header('HTTP/1.1 200 Transaction Pending');
   echo "Transaction Pending, awaiting confirmation.";
   }
   if($confirms > 5)
     {
         header('HTTP/1.1 201 Transaction Confirmed');
         echo "Transaction Confirmed";
         addVerified($TxID,$log);
     }
}
elseif($confirms == -1)
{
   header('HTTP/1.1 303 Transaction amount lower than specified');
   echo "Transaction amount lower than specified";
}
else
{
   header('HTTP/1.1 305 Transaction Not Found');
   echo "Transaction Not Found";
}




function checkTransfer($TxID = "62f1085c06aa841bcca8c3ade28c64429c83204a56bf072cd3ed76e22c1495be", $toAddress = "15knn9nNy7uzgC3nsaupUYB5n3PYXmtnDy", $satoshi = 100000)
{
global $verifyReceiver;
global $verifyAmount;

$BlockExplorer = "https://live.blockcypher.com/";
$BlockExplorerAPILink = "https://api.blockcypher.com/v1/btc/main/txs/".$TxID."?limit=50&includeHex=true"; 

// TRY THIS WITH 62f1085c06aa841bcca8c3ade28c64429c83204a56bf072cd3ed76e22c1495be

$TxLink = "https://live.blockcypher.com/btc/tx/".$TxID;


$result = json_decode(file_get_contents($BlockExplorerAPILink),true);

if (!$result){
   header('HTTP/1.1 306 Transaction ID may be invalid');
    exit("Unable to get information about that transaction id.");
    
}

$block_hash = $result['block_hash'];
$block_height = $result['block_height'];
$block_index = $result['block_index'];
$hash = $result['hash'];
$addresses = $result['addresses'];
$total = $result['total']; 
$fees = $result['fees']; // fees in satoshis
$size = $result['size']; // size in kb
$preference = $result['preference'];
$relayed_by = $result['relayed_by']; // IP address that sends the transaction
$confirmed = $result['confirmed']; // the first confirmation at what time?
$received = $result['received']; // At what the transaction will be received
$ver = $result['ver']; // version
$lock_time = $result['lock_time']; // lock time
$double_spend = $result['double_spend']; // there are any double spends
$vin_sz = $result['vin_sz']; // n
$vout_sz = $result['vout_sz']; // n
$confirmations = $result['confirmations']; // how much confirmations in the transaction
$confidence = $result['confidence']; // confidence
$inputs = $result['inputs'];
$outputs = $result['outputs'];

$prev_hash = $inputs['prev_hash'];
$output_index = $inputs['output_index'];
$script = $inputs['script'];
$output_value = $inputs['output_value'];
$sequence = $inputs['sequence'];
$addresses_inputs = $inputs['addresses'];

$outputs_value = $outputs['value'];
$scripto = $outputs['script'];
$scripto_type = $outputs['script_type'];

// Confirmation set
$ok = false;
if ($confirmations > 0)
{
if ($verifyReceiver && $verifyAmount)
{
if($addresses[1] == $toAddress && $total >= $satoshi)
      {
        return $confirmations;
      }
elseif ($addresses[1] == $toAddress && $total < $satoshi)
   { 
     return -1;
   }
}
else if ($verifyReceiver & !$verifyAmount)
{
 if($addresses[1] == $toAddress)
   {
     return $confirmations;
   }
}
else if ($verifyAmount & !$verifyReceiver)
{
  if($total >= $satoshi)
   {
     return $confirmations;
   }
   else
   { 
     return -1;
   }
}
else if (!$verifyAmount &! $verifyReceiver)
{
 return $confirmations;
}
}
return 0;
}

?>
