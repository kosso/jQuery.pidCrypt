/**
 *
 * jQuery plugin to impliment the pidCrypt library
 *
 * FEATURES:
 * - Requests OpenSSL private/public key from server or searches local
 *   storage (local, session or cookie)
 * - Private key generated is registered as a session variable
 *   associated with computer IP
 * - Private key is also password protected with comptuters IP address
 * - Private key is stored in HTML5 localStorage, sessionStorage or a cookie
 * - Dynamically parses specified HTML form elements and applies
 *   public key RSA encryption when submitted
 *
 * REQUIREMENTS:
 * - pidCrypt library https://www.pidder.com/pidcrypt/
 * - jQuery cookie plugin http://plugins.jquery.com/files/jquery.cookie.js.txt (optional)
 *
 * OPTIONS:
 * - name:    Unique identifier for storage mechanism
 * - key:     If visiting user has a private key on the server you can assign this
 *            dynamically with their public key
 * - bits:    Default is 256. 128, 192 & 256 are supported values. This is used ONLY
 *            when the 'where' configuration option is set to decrypt on the client.
 * - proxy:   Server location (defaults to form action attribute)
 * - storage: HTML5 localStorage, sessionStorage and cookies supported
 * - type:    Default is asymmetric. Alternative option is symmetric.
 *            WARNING: If this is set to client symmetric AES-CBC encryption
 *            is used and a SSL connection is recommended
 * - encode:  Default is false. Set this to true if experiencing decryption problems
 * - decrypt: Allows for decrypted data on server to be sent back to client (recommended only for demo puposes)
 * - debug:   Default is false. Set this to true if you wish to see output of the
 *            processing. Not for production use.
 * 
 * Author: Jason Gerfen
 * Email: jason.gerfen@gmail.com
 * Copyright: Jason Gerfen
 *
 * License: GPL
*
* Fixes and updates  by Kosso
 *
 */

(function($){

 /* parse public/private key function
  (Copyright https://www.pidder.com/pidcrypt/?page=demo_rsa-encryption)
 */
 $.certParser = function(cert) {
 var lines = cert.split('\n');
 var read = false;
 var b64 = false;
 var end = false;
 var flag = '';
 var retObj = {};
 retObj.info = '';
 retObj.salt = '';
 retObj.iv;
 retObj.b64 = '';
 retObj.aes = false;
 retObj.mode = '';
 retObj.bits = 0;
 for(var i=0; i< lines.length; i++){
  flag = lines[i].substr(0,9);
  if(i==1 && flag != 'Proc-Type' && flag.indexOf('M') == 0)//unencrypted cert?
  b64 = true;
  switch(flag){
   case '-----BEGI':
    read = true;
    break;
   case 'Proc-Type':
    if(read)
     retObj.info = lines[i];
     break;
   case 'DEK-Info:':
    if(read){
     var tmp = lines[i].split(',');
     var dek = tmp[0].split(': ');
     var aes = dek[1].split('-');
     retObj.aes = (aes[0] == 'AES')?true:false;
     retObj.mode = aes[2];
     retObj.bits = parseInt(aes[1]);
     retObj.salt = tmp[1].substr(0,16);
     retObj.iv = tmp[1];
    }
    break;
   case '':
    if(read)
     b64 = true;
     break;
   case '-----END ':
    if(read){
     b64 = false;
     read = false;
    }
    break;
   default:
    if(read && b64)
     retObj.b64 += pidCryptUtil.stripLineFeeds(lines[i]);
  }
 }
 return retObj;
 }

 /* Generate random public key */
 $.genKey = function(len) {
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVXYZ1234567890';
  var key = '';
  for (x=0;x<len;x++) {
   i = Math.floor(Math.random() * 62);
   key += chars.charAt(i);
  }
  return key;
 }

 /* Store public key in specified storage mechanism */
 $.setKey = function(type, name, key) {
  var x = false;
  type = ($.validateStorage(type)) ? type : 'cookie';
  switch(type) {
   case 'localStorage':
    x = $.setLocal(name, key);
   break;
   case 'sessionStorage':
    x = $.setSession(name, key);
    break;  
   case 'cookie':
    x = $.setCookie(name, key);
   break; 
  default:
    x = $.setLocal(name, key);
  }
  return x;
 }

 /* Get public key from specified storage mechanism */
 $.getKey = function(type, name) {
  var x = false;
  type = ($.validateStorage(type)) ? type : 'cookie';
  switch(type) {
   case 'localStorage':
    x = $.getLocal(name);
   break;
   case 'sessionStorage':
    x = $.getSession(name);
   break;
   case 'cookie':
    x = $.getCookie(name);
   break;
   default:
    x = $.getLocal(name);
  }
  return x;
 }

 /* localStorage setter */
 $.setLocal = function(name, key) {
  return (localStorage.setItem(name+'-key', key)) ? true : false;
 }

 /* sessionStorage setter */
 $.setSession = function(name, key) {
  return (sessionStorage.setItem(name+'-key', key)) ? true : false;
 }

 /* cookie setter */
 $.setCookie = function(name, key) {
  if (typeof $.cookie == 'function') {
   return ($.cookie(name+'-key', key, {expires: 7})) ? true : false;
  } else {
   return false;
  }
 }

 /* localStorage getter */
 $.getLocal = function(name) {
  return (localStorage.getItem(name+'-key')) ? localStorage.getItem(name+'-key') : false;
 }

 /* sessionStorage getter */
 $.getSession = function(name) {
  return (sessionStorage.getItem(name+'-key')) ? sessionStorage.getItem(name+'-key') : false;
 }

 /* cookie getter */
 $.getCookie = function(name) {
  if (typeof $.cookie == 'function') {
   return ($.cookie(name+'-key')) ? $.cookie(name+'-key') : false;
  } else {
   return false;
  }
 }

 /* update status area with encrypted text */
 $.updateFormEnc = function(data) {
  $.each(data, function(k,v) {
   if (typeof v == 'object') {
    var x = '';
    $.each(v, function(a, b) {
     x += b;
    });
   }
   v = (x) ? x : v;
   if ($.validateElement(k+'-enc')==true) {
    $('#'+k+'-enc').html(v);
   }
  });
 }

 /* update status area with decrypted text */
 $.updateFormDenc = function(data, options) {
  if (options.debug==true) { $.genDebug(data, 'Data after processing', '<hr/>'); } 
  $.each(data, function(k,v) {
   if ($.validateElement(k+'-denc')==true) {
    $('#'+k+'-denc').html(v);
   }
  });
 }

 /* validate page element integrity */
 $.validateElement = function(element) {
  return (($('#'+element))&&($('#'+element).length>0)) ? true : false;
 }

 /* validate string integrity */
 $.validateString = function(string) {
  return ((string=='false')||(string.length==0)||(!string)||(string==null)||(string=='')||(typeof string=='undefined')) ? false : true;
 }

 /* validate localStorage/sessionStorage functionality */
 $.validateStorage = function(type) {
    return ((window[type])&&(typeof window[type]=='object')) ? true : false;
 }


 /* split string if greater then bits allow for RSA limitations */
 $.strLength = function(name, str, options) {
  return (parseInt(str.length) > 80) ?  $.strSplit(name, str) : str;
 }

 /* does the actual splitting */
 $.strSplit = function(name, str) {
  var t = str.length/80;
  var y = new Object();
  var x=0; var z=80;
  for (var i=0; i<t; i++) {
   if (i>0) { x=x+80; z=z+80; }
   if (str.slice(x, z).length>0) {
    y[i] = str.slice(x, z);
   }
  }
  return y;
 }

 /* handle encryption of form elements */
 $.encryptForm = function(form, options) {
  var data = {};
  /* setup arguments for encryption */
  options.bits = parseInt(options.bits);
  /* pass arguments to proxy */
  data['server-decrypt'] = (options.type=='asymmetric') ? true : false;
  data['decrypt-response'] = (options.decrypt==true) ? true : false;
  /* parse public key */
  var params = $.certParser(decodeURIComponent(options.key));
  if(params.b64) {
   var x = pidCryptUtil.decodeBase64(params.b64);
   var rsa = new pidCrypt();
   var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(x));
   var tree = asn.toHexTree();
   pidCrypt.RSA.prototype.setPublicKeyFromASN(tree);
  }
  /* begin looping over form elements and encrypting */
  $.each($('#'+form+' :text, :password, :file, input:checkbox:checked, input:radio:checked, textarea'), function(k, v){
   if ($.validateString(v.value)!==false) {
    /* check string length based on bit length */
    var y = (options.type=='asymmetric') ? $.strLength(v.name, v.value, options) : v.value;
    if (typeof y == 'object') {
     data[v.name] = {};
     $.each(y, function(a, b) {
      data[v.name][a] = $.encryptFormHelper(options, null, v.name, b, x);
     });
    } else {
     /* initialize AES CBC methods in pidCrypt libs */
     var aes = new pidCrypt.AES.CBC();
     var x = $.encryptSeeder(options, aes);
     data[v.name] = $.encryptFormHelper(options, aes, v.name, y, x);
    }
   }
  });
  if (options.debug==true) { $.genDebug(data, 'Cipher text before sending to server', '<hr/>'); }
  return data;
 }

 /* form encryptor helper */
 $.encryptFormHelper = function(options, aes, nm, v, x) {
  if (options.type=='asymmetric') {
   /* RSA public key encryption */
   var data = (options.encode==true) ? encodeURIComponent(pidCrypt.RSA.prototype.encrypt(v)) : pidCrypt.RSA.prototype.encrypt(v);
  } else {
   /* AES symmetric encryption */
   var data = (options.encode==true) ? encodeURIComponent(aes.encryptText(v, options.key, {nBits:options.bits})) : aes.encryptText(v, options.key, {nBits:options.bits});
  }
  return data;
 }

 $.encryptSeeder = function(options, aes) {
  options.random = $.genKey(128);
  options.iv = $.genKey(16);
  var x = aes.createKeyAndIv({password:options.random, salt:options.iv, bits:options.bits});
  return x;
 }

 /* handle decryption of server data */
 $.decryptForm = function(response, options) {
  /* initialize AES CBC methods in pidCrypt libs */
  var aes = new pidCrypt.AES.CBC();
  options.bits = parseInt(options.bits);
  options.iv = parseInt(options.iv);
  var data = {};
  $.each(response, function(k, v){
   if ($.validateString(v)!==false) {
    data[k] = (options.encode==true) ? encodeURIComponent(aes.decryptText(pidCryptUtil.stripLineFeeds(v), options.key, {nBits:options.bits})) : aes.decryptText(pidCryptUtil.stripLineFeeds(v), options.key, {nBits:options.bits});
   }
  });
  return data;
 }

 /* get and set public key */
 $.requestPublicKey = function(options) {
  $.ajax({
   data: 'ssl-key=true',
   type: 'post',
   url: options.proxy,
   success: function(response) {
    options.key = (options.encode) ? encodeURIComponent(response) : response;
    $.setKey(options.storage, options.name, options.key);
   }
  });
  return false;
 }

 /* handle debugging output */
 $.genDebug = function(data, title, spacer) {
  $('#debug').append('<h2>'+title+'</h2>');
  if (typeof data == 'object') {
   $.each(data, function(k, v) {
    if (typeof v == 'object') {
     var x = '';
     $.each(v, function(a, b) {
      x += b;
     });
    }
    v = (x) ? x : v;
    $('#debug').append('<b>'+k+'</b> => '+v+'<br/><br/>');
   });
  } else {
   $('#debug').append(data);
  }
  $('#debug').append(spacer);
 }

 /* the plug-in meat and potatoes */
 $.fn.pidCrypt = function(options) {

  /* default options */
  var defaults = {
   name:    'jQuery.pidCrypt',      // Plugin name (unique ID for local, session or cookie storage id)
   key:     '',                     // place holder for key
   random:  '',                     // place holder for random secret (non-configurable option)
   bits:    256,                    // key size (128, 192, 256 supported)
   proxy:   $(this).attr('action'), // Server side processor
   form:    $(this).attr('id'),     // form element ID
   storage: 'localStorage',         // localStorage || sessionStorage || cookie (cookie storage requires jQuery cookie plugin)
   type:    'asymmetric',           // asymmetric || symmetric (to decrypt on server leave default, to decrypt response from server use symmetric)
   encode:  false,                  // encode for URI? true || false
   debug:   false,                  // enable debugging output? true || false (requires <div id="debug"></div> object)
   decrypt: false                   // Allow server to send decrypted data back? true || false (DEMO MODE OPTION AS THIS SENDS DECRYPTED DATA OVER WIRE)
  };

  /* put it in chains */
  return this.each(function() {

   /* merge specified options with defaults */
   if (options) {
    options = $.extend(defaults, options);
   }

   /* does this user have a key? */
   if (!options.key) {
    options.key = $.getKey(options.storage, options.name);
    /* generate a key or get one from the server then store it locally */
    if ((!options.key)&&($.validateString(options.key)==false)) {
     options.key = $.requestPublicKey(options);
     $.setKey(options.storage, options.name, options.key);
    }
   }

   /* debuging enabled? show some config values */
   if (options.debug==true) { $.genDebug(options, 'Configuration Options:<br/>', '<hr/>'); }

   /* hijack the form and process accordingly */
   $('.'+options.form).live('submit', function(e) {

    /* get our form data */
    var data = $.encryptForm(options.form, options);

    /* encrypt it all before sending */
    $.updateFormEnc(data);

    /* send it off */
    var denc = {};
    $.ajax({
     data: data,
     type: $(this).attr('method'),
     url: options.proxy,
     dataType: 'json',
     success: function(response) {
      (options.type=='asymmetric') ? $.updateFormDenc(response, options) : $.updateFormDenc($.decryptForm(response, options), options);
     }
    });
    return false;
   });
   return false;
  });
 };
})(jQuery);