<?php
namespace noraziz\ci4aauth\Database\Migrations;

use CodeIgniter\Database\Migration;

class BaseTables extends Migration
{
	
	public function up()
	{
		$tbl_attrs = ['ENGINE' => 'InnoDB'];
		
		## Create Table aauth_group_to_group
		$this->forge->addField(array(
			'group_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'subgroup_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
		));
		$this->forge->addKey("subgroup_id",true);
		$this->forge->createTable("aauth_group_to_group", TRUE, $tbl_attrs);

		## Create Table aauth_groups
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'name' => array(
				'type' => 'VARCHAR',
				'constraint' => 100,
				'null' => TRUE,

			),
			'definition' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_groups", TRUE, $tbl_attrs);

		## Create Table aauth_login_attempts
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 11,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'ip_address' => array(
				'type' => 'VARCHAR',
				'constraint' => 39,
				'null' => TRUE,
				'default' => '0',

			),
			'timestamp' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'login_attempts' => array(
				'type' => 'TINYINT',
				'constraint' => 2,
				'null' => TRUE,
				'default' => '0',

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_login_attempts", TRUE, $tbl_attrs);

		## Create Table aauth_perm_to_group
		$this->forge->addField(array(
			'perm_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'group_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
		));
		$this->forge->addKey("group_id",true);
		$this->forge->createTable("aauth_perm_to_group", TRUE, $tbl_attrs);

		## Create Table aauth_perm_to_user
		$this->forge->addField(array(
			'perm_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'user_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
		));
		$this->forge->addKey("user_id",true);
		$this->forge->createTable("aauth_perm_to_user", TRUE, $tbl_attrs);

		## Create Table aauth_perms
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'name' => array(
				'type' => 'VARCHAR',
				'constraint' => 100,
				'null' => TRUE,

			),
			'definition' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_perms", TRUE, $tbl_attrs);

		## Create Table aauth_pms
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'sender_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'receiver_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'title' => array(
				'type' => 'VARCHAR',
				'constraint' => 255,
				'null' => FALSE,

			),
			'message' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
			'date_sent' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'date_read' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'pm_deleted_sender' => array(
				'type' => 'INT',
				'constraint' => 1,
				'null' => TRUE,

			),
			'pm_deleted_receiver' => array(
				'type' => 'INT',
				'constraint' => 1,
				'null' => TRUE,

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_pms", TRUE, $tbl_attrs);

		## Create Table aauth_user_to_group
		$this->forge->addField(array(
			'user_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'group_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
		));
		$this->forge->addKey("group_id",true);
		$this->forge->createTable("aauth_user_to_group", TRUE, $tbl_attrs);

		## Create Table aauth_user_variables
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'user_id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,

			),
			'data_key' => array(
				'type' => 'VARCHAR',
				'constraint' => 100,
				'null' => FALSE,

			),
			'value' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_user_variables", TRUE, $tbl_attrs);

		## Create Table aauth_users
		$this->forge->addField(array(
			'id' => array(
				'type' => 'INT',
				'constraint' => 1,
				'unsigned' => TRUE,
				'null' => FALSE,
				'auto_increment' => TRUE
			),
			'email' => array(
				'type' => 'VARCHAR',
				'constraint' => 100,
				'null' => FALSE,

			),
			'pass' => array(
				'type' => 'VARCHAR',
				'constraint' => 64,
				'null' => FALSE,

			),
			'username' => array(
				'type' => 'VARCHAR',
				'constraint' => 100,
				'null' => TRUE,

			),
			'banned' => array(
				'type' => 'TINYINT',
				'constraint' => 1,
				'null' => TRUE,
				'default' => '0',

			),
			'last_login' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'last_activity' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'date_created' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'forgot_exp' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
			'remember_time' => array(
				'type' => 'DATETIME',
				'null' => TRUE,

			),
			'remember_exp' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
			'verification_code' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
			'totp_secret' => array(
				'type' => 'VARCHAR',
				'constraint' => 16,
				'null' => TRUE,

			),
			'ip_address' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
		));
		$this->forge->addKey("id",true);
		$this->forge->createTable("aauth_users", TRUE, $tbl_attrs);
	 }
	 
	 

	public function down()
	{
		### Drop table aauth_group_to_group ##
		$this->forge->dropTable("aauth_group_to_group", TRUE);
		### Drop table aauth_groups ##
		$this->forge->dropTable("aauth_groups", TRUE);
		### Drop table aauth_login_attempts ##
		$this->forge->dropTable("aauth_login_attempts", TRUE);
		### Drop table aauth_perm_to_group ##
		$this->forge->dropTable("aauth_perm_to_group", TRUE);
		### Drop table aauth_perm_to_user ##
		$this->forge->dropTable("aauth_perm_to_user", TRUE);
		### Drop table aauth_perms ##
		$this->forge->dropTable("aauth_perms", TRUE);
		### Drop table aauth_pms ##
		$this->forge->dropTable("aauth_pms", TRUE);
		### Drop table aauth_user_to_group ##
		$this->forge->dropTable("aauth_user_to_group", TRUE);
		### Drop table aauth_user_variables ##
		$this->forge->dropTable("aauth_user_variables", TRUE);
		### Drop table aauth_users ##
		$this->forge->dropTable("aauth_users", TRUE);
	}
}
