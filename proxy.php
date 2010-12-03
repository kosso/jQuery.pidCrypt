<?php
/* openssl settings */
$settings['config']['cnf']                = array('config' => 'openssl.cnf', 'x509_extensions' => 'usr_cert');
$settings['config']['expires']            = 365;
$settings['config']['private']            = '';
$settings['config']['algorithm']          = '';
$settings['config']['digest']             = '';
$settings['config']['keybits']            = '';
$settings['dn']['countryName']            = '';
$settings['dn']['stateOrProvinceName']    = '';
$settings['dn']['localityName']           = '';
$settings['dn']['organizationName']       = '';
$settings['dn']['organizationalUnitName'] = '';
$settings['dn']['commonName']             = '';
$settings['dn']['emailAddress']           = '';

/* session init */
session_start();

/* does the class exist */
if (file_exists('class.openssl.php')) {
 include 'class.openssl.php';
 /* handle for class object */
 $openssl = openssl::instance($settings);
 if (is_object($openssl)) {
  if (!empty($_POST)) {
   $post = $_POST;
   /*
    * public key?
    * If you used a database to store existing keys
    * add the support after this conditional
    */
   if ((!empty($post['ssl-key']))&&($post['ssl-key']==='true')) {
    $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'] = $openssl->genPriv($_SERVER['REMOTE_ADDR']);
    $pub = $openssl->genPub();
    $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'] = $pub['key'];
    echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'];
    exit;
   }
   if ((!empty($post['server-decrypt']))&&($post['server-decrypt']==='true')) {
    if ((!empty($post['decrypt-response']))&&($post['decrypt-response']==='true')) {
     echo json_encode(helper($post, $openssl));
    } else {
     echo json_encode($post);
    }
   } else {
    echo json_encode($post);
   }
  }
 }
}
function helper($array, $openssl)
{
 foreach($array as $key => $value) {
  if (is_array($value)) {
   foreach($value as $k => $v) {
    $b[$k] = $openssl->privDenc($v, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']);
   }
   $a[$key] = combine($b);
  } else {
   $a[$key] = $openssl->privDenc($value, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']);
  }
 }
 return $a;
}
function combine($array) {
 $a = '';
 foreach($array as $k => $v) {
  $a .= $v;
 }
 return $a;
}
?>
