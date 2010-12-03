<?php
/**
 * Handle openssl encryption functionality
 *
 * Creates public / private OpenSSL keys
 * Used to encrypt & decrypt data with supplied keys
 * Optional file output methods
 *
 * LICENSE: This source file is subject to version 3.01 of the GPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/licenses/gpl.html.  If you did not receive a copy of
 * the GPL License and are unable to obtain it through the web, please
 *
 * @category   encryption
 * @package    phpMyFramework
 * @author     Original Author <jason.gerfen@gmail.com>
 * @copyright  2010 Jason Gerfen
 * @license    http://www.gnu.org/licenses/gpl.html  GPL License 3
 * @version    0.1
 */

class openssl
{
 protected static $instance;
 private $handle=NULL;
 private $opt=array();
 private $dn=array();
 public $output;
 private function __construct($configuration)
 {
  if (function_exists('openssl_pkey_new')) {
   $this->setOpt($configuration);
   $this->setDN($configuration);
   return;
  } else {
   echo 'The openssl extensions are not loaded.';
   unset($instance);
   exit;
  }
 }
 public static function instance($configuration)
 {
  if (!isset(self::$instance)) {
   $c = __CLASS__;
   self::$instance = new self($configuration);
  }
  return self::$instance;
 }
 private function setOpt($configuration)
 {
  $this->opt = $configuration['config'];
 }
 private function setDN($configuration)
 {
  $this->dn = $configuration['dn'];
 }
 public function genPriv($password)
 {
  $this->handle = openssl_pkey_new();
  openssl_pkey_export($this->handle, $privatekey, $password);
  return $privatekey;
 }
 public function genPub()
 {
  $results = openssl_pkey_get_details($this->handle);
  return $results;
 }
 public function decodeCert($certificate)
 {
  return openssl_x509_parse($certificate);
 }
 private function signReq($dn, $private, $opt)
 {
  return ((is_array($opt))&&(!empty($opt))) ? openssl_csr_new($dn, $private, $opt) : openssl_csr_new($dn, $private);
 }
 private function sign($csr, $private, $password, $days, $opt, $ca=NULL)
 {
  $a = openssl_pkey_get_private($private, $password);
  return openssl_csr_sign($csr, $ca, $a, $days, $opt);
 }
 public function enc($private, $data, $password)
 {
  if ((!empty($private))&&(!empty($data))) {
   $res = openssl_get_privatekey($private, $password);
   openssl_private_encrypt($data, $this->output, $res);
   return $this->output;
  } else {
   return FALSE;
  }
 }
 public function pubDenc($crypt, $key)
 {
  $res = (is_array($key)) ? openssl_get_publickey($key['key']) : openssl_get_publickey($key);
  ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ? openssl_public_decrypt($this->convertBin($crypt), $this->output, $res) : openssl_public_decrypt($crypt, $this->output, $res);
  return ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ? base64_decode($this->output) : $this->output;
 }
 public function privDenc($crypt, $key, $pass)
 {
  $res = (is_array($key)) ? openssl_get_privatekey($key['key'], $pass) : openssl_get_privatekey($key, $pass);
  ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ? openssl_private_decrypt($this->convertBin($crypt), $this->output, $res) : openssl_private_decrypt($crypt, $this->output, $res);
  return ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ? base64_decode($this->output) : $this->output;
 }
 public function aesEnc($data, $cipher='aes-256-cbc', $password, $iv='', $raw=false)
 {
  return openssl_encrypt($data, $cipher, $password, $raw, $iv);
 }
 public function aesDenc($data, $cipher='aes-256-cbc', $password, $iv='', $raw=false)
 {
  return openssl_decrypt($data, $cipher, $password, $raw, $iv);
 }
 private function convertBin($key)
 {
  $data='';
  $hexLength = strlen($key);
  if ($hexLength % 2 != 0 || preg_match("/[^\da-fA-F]/", $key)) { $binString = -1; }
  unset($binString);
  for ($x = 1; $x <= $hexLength / 2; $x++) {
   $data .= chr(hexdec(substr($key, 2 * $x - 2, 2)));
  }
  return $data;
 }
}
?>
