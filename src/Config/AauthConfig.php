<?php

namespace noraziz\ci4aauth\Config;

/*
| -------------------------------------------------------------------
| Aauth Config
| -------------------------------------------------------------------
| A library Basic Authorization for CodeIgniter 4.x
|
|
*/

use CodeIgniter\Config\BaseConfig;
define('CI4_LIB_AAUTH_TABLEPREFIX', 'aauth_');

class AauthConfig extends BaseConfig
{
	/*
	|--------------------------------------------------------------------------
	| Protection Mode
	|--------------------------------------------------------------------------
	|
	| Activate protection mode when codeigniter is in development mode.
	| If user don't have permisssion to see the page he will be redirected the page spesificed.
	*/
	public $no_permission = false;
	
	
	
	/*
	|--------------------------------------------------------------------------
	| Database Config
	|--------------------------------------------------------------------------
	|
	| The configuration database profile (definied in config/database.php)
	|
	| DB Table definitions
	|   'tbl_users'				The table which contains users
	|   'tbl_groups'			The table which contains groups
	|   'tbl_user_to_group'		The table which contains join of users and groups
	|   'tbl_perms'				The table which contains permissions
	|   'tbl_perm_to_group'		The table which contains permissions for groups
	|   'tbl_perm_to_user'		The table which contains permissions for users
	|   'tbl_pms'				The table which contains private messages
	|   'tbl_user_variables'	The table which contains users variables
	*/
	public $db_profile = 'default';
	
	//private const CI4_LIB_AAUTH_TABLEPREFIX = 'aauth_';
	
	public $tbl_users          = CI4_LIB_AAUTH_TABLEPREFIX . 'users';
	public $tbl_groups         = CI4_LIB_AAUTH_TABLEPREFIX . 'groups';
	public $tbl_group_to_group = CI4_LIB_AAUTH_TABLEPREFIX . 'group_to_group';
	public $tbl_user_to_group  = CI4_LIB_AAUTH_TABLEPREFIX . 'user_to_group';
	public $tbl_perms          = CI4_LIB_AAUTH_TABLEPREFIX . 'perms';
	public $tbl_perm_to_group  = CI4_LIB_AAUTH_TABLEPREFIX . 'perm_to_group';
	public $tbl_perm_to_user   = CI4_LIB_AAUTH_TABLEPREFIX . 'perm_to_user';
	public $tbl_pms            = CI4_LIB_AAUTH_TABLEPREFIX . 'pms';
	public $tbl_user_variables = CI4_LIB_AAUTH_TABLEPREFIX . 'user_variables';
	public $tbl_login_attempts = CI4_LIB_AAUTH_TABLEPREFIX . 'login_attempts';
	
	
	
	/*
	|--------------------------------------------------------------------------
	| Group
	|--------------------------------------------------------------------------
	|
	|   'admin_group'  			Name of admin group
	|   'default_group'   		Name of default group, the new user is added in it
	|   'public_group'    		Name of Public group , people who not logged in
	*/
	public $admin_group   = 'admin';
	public $default_group = 'default';
	public $public_group  = 'public';
	
	
	
	/*
	|--------------------------------------------------------------------------
	| General Protection
	|--------------------------------------------------------------------------
	|
	|   'ddos_protection'					Enables the DDoS Protection, user will be banned temporary when he exceed the login 'try'
	|   'max_login_attempt'             	Login attempts time interval (default 10 times in one hour)
	|   'max_login_attempt_time_period' 	Period of time for max login attempts (default "5 minutes")
	|   'remove_successful_attempts'    	Enables removing login attempt after successful login
	|   'login_with_name'               	Login Identificator, if TRUE username needed to login else email address.
	|   'remember'                  		Remember time (in relative format) elapsed after connecting and automatic LogOut for usage with Cookies
	|             							  Relative Format (e.g. '+ 1 week', '+ 1 month', '+ first day of next month') 
	|             							  for details see http://php.net/manual/de/datetime.formats.relative.php
	|
	|   'char_max'							Maximum char long for Password
	|   'char_min'							Minimum char long for Password
	|   'additional_valid_chars'			Additional valid chars for username. Non alphanumeric characters that are allowed by default
	|
	|   'hash'								Name of selected hashing algorithm (e.g. "md5", "sha256", "haval160,4", etc..)
	|                                         Please, run hash_algos() for know your all supported algorithms
	|   'use_password_hash'					Enables to use PHP's own password_hash() function with BCrypt, needs PHP5.5 or higher
	|   'password_hash_algo'				Password_hash algorithm (PASSWORD_DEFAULT, PASSWORD_BCRYPT) 
	|                       				  for details see http://php.net/manual/de/password.constants.php
	|   'password_hash_options'				Password_hash options array 
	|                                         for details see http://php.net/manual/en/function.password-hash.php
	|
	|   'pm_encryption'						Enables PM Encryption, needs configured CI Encryption Class.
	|                                         for details see: http://www.codeigniter.com/userguide2/libraries/encryption.html
	|   'pm_cleanup_max_age'				PM Cleanup max age (in relative format), PM's are older than max age get deleted with 'cleanup_pms()'
	|                                         Relative Format (e.g. '2 week', '1 month') 
	|                                         for details see http://php.net/manual/de/datetime.formats.relative.php
	*/
	public $ddos_protection               = true;
	public $max_login_attempt             = 10;
	public $max_login_attempt_time_period = "5 minutes";
	public $remove_successful_attempts    = true;
	public $login_with_name               = false;
	public $remember                      = ' +3 days';
	
	public $char_max               = 13;
	public $char_min               = 5;
	public $additional_valid_chars = array();
	
	public $hash                  = 'sha256';
	public $use_password_hash     = false;
	public $password_hash_algo    = PASSWORD_DEFAULT;
	public $password_hash_options = array();
	
	public $pm_encryption      = false;
	public $pm_cleanup_max_age = "3 months";
	
	
	
	/*
	|--------------------------------------------------------------------------
	| Re-Captcha
	|--------------------------------------------------------------------------
	|
	|   'recaptcha_active'                Enables reCAPTCHA (for details see www.google.com/recaptcha/admin)
	|   'recaptcha_login_attempts'        Login Attempts to display reCAPTCHA
	|   'recaptcha_siteKey'               The reCAPTCHA siteKey
	|   'recaptcha_secret'                The reCAPTCHA secretKey
	*/
	public $recaptcha_active         = false;
	public $recaptcha_login_attempts = 4;
	public $recaptcha_siteKey        = '';
	public $recaptcha_secret         = '';
	
	
	
	/*
	|--------------------------------------------------------------------------
	| OTP
	|--------------------------------------------------------------------------
	|
	|   'totp_active'                     Enables the Time-based One-time Password Algorithm
	|   'totp_only_on_ip_change'          TOTP only on IP Change
	|   'totp_reset_over_reset_password'  TOTP reset over reset Password
	|   'totp_two_step_login'             Enables TOTP two step login 
	|   'totp_two_step_login_redirect'    Redirect path to TOTP Verification page used by control() & is_allowed()
	*/
	public $totp_active                    = false;
	public $totp_only_on_ip_change         = false;
	public $totp_reset_over_reset_password = false;
	public $totp_two_step_login_active     = false;
	public $totp_two_step_login_redirect   = '/account/twofactor_verification/';
	
	
	
	/*
	|--------------------------------------------------------------------------
	| Admin Contact
	|--------------------------------------------------------------------------
	|
	|   'email'				Sender email address, used for remind_password, send_verification and reset_password
	|   'name'				Sender name, used for remind_password, send_verification and reset_password
	|   'email_config'		Array of Config for CI's Email Library
	*/
	public $email        = 'admin@admin.com';
	public $name         = 'Nor Aziz';
	public $email_config = false;
	
	
	
	/*
	|--------------------------------------------------------------------------
	| Page Navigation
	|--------------------------------------------------------------------------
	|
	|   'verification'				User Verification, if TRUE sends a verification email on account creation.
	|   'verification_link'			Link for verification without site_url or base_url
	|   'reset_password_link'		Link for reset_password without site_url or base_url
	*/
	public $verification        = false;
	public $verification_link   = '/account/verification/';
	public $reset_password_link = '/account/reset_password/';
	
}
