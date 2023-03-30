<?php defined('BASEPATH') OR exit('No direct script access allowed');

namespace noraziz\ci4aauth\Database\Migrations;

use CodeIgniter\Database\Migration;

class BaseTables extends Migration {

	public function up() {

		## Create Table aauth_group_to_group
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("subgroup_id",true);
		$this->dbforge->create_table("aauth_group_to_group", TRUE);
		$this->db->query('ALTER TABLE  `aauth_group_to_group` ENGINE = InnoDB');

		## Create Table aauth_groups
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_groups", TRUE);
		$this->db->query('ALTER TABLE  `aauth_groups` ENGINE = InnoDB');

		## Create Table aauth_login_attempts
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_login_attempts", TRUE);
		$this->db->query('ALTER TABLE  `aauth_login_attempts` ENGINE = InnoDB');

		## Create Table aauth_perm_to_group
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("group_id",true);
		$this->dbforge->create_table("aauth_perm_to_group", TRUE);
		$this->db->query('ALTER TABLE  `aauth_perm_to_group` ENGINE = InnoDB');

		## Create Table aauth_perm_to_user
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("user_id",true);
		$this->dbforge->create_table("aauth_perm_to_user", TRUE);
		$this->db->query('ALTER TABLE  `aauth_perm_to_user` ENGINE = InnoDB');

		## Create Table aauth_perms
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_perms", TRUE);
		$this->db->query('ALTER TABLE  `aauth_perms` ENGINE = InnoDB');

		## Create Table aauth_pms
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_pms", TRUE);
		$this->db->query('ALTER TABLE  `aauth_pms` ENGINE = InnoDB');

		## Create Table aauth_user_to_group
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("group_id",true);
		$this->dbforge->create_table("aauth_user_to_group", TRUE);
		$this->db->query('ALTER TABLE  `aauth_user_to_group` ENGINE = InnoDB');

		## Create Table aauth_user_variables
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_user_variables", TRUE);
		$this->db->query('ALTER TABLE  `aauth_user_variables` ENGINE = InnoDB');

		## Create Table aauth_users
		$this->dbforge->add_field(array(
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
		$this->dbforge->add_key("id",true);
		$this->dbforge->create_table("aauth_users", TRUE);
		$this->db->query('ALTER TABLE  `aauth_users` ENGINE = InnoDB');

		## Create Table appsms_core_company
		$this->dbforge->add_field(array(
			'companyID' => array(
				'type' => 'VARCHAR',
				'constraint' => 20,
				'null' => FALSE,

			),
			'nama' => array(
				'type' => 'VARCHAR',
				'constraint' => 50,
				'null' => FALSE,

			),
			'alamat' => array(
				'type' => 'VARCHAR',
				'constraint' => 512,
				'null' => TRUE,

			),
			'telepon' => array(
				'type' => 'VARCHAR',
				'constraint' => 50,
				'null' => TRUE,

			),
			'website' => array(
				'type' => 'VARCHAR',
				'constraint' => 255,
				'null' => TRUE,

			),
			'email' => array(
				'type' => 'VARCHAR',
				'constraint' => 255,
				'null' => TRUE,

			),
			'is_active' => array(
				'type' => 'ENUM("Y","N")',
				'null' => FALSE,
				'default' => 'Y',

			),
			'keterangan' => array(
				'type' => 'TEXT',
				'null' => TRUE,

			),
			'create_time' => array(
				'type' => 'DATETIME',
				'null' => FALSE,

			),
			'`update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP',
		));
	 }
	 
	 

	public function down()	{
		### Drop table aauth_group_to_group ##
		$this->dbforge->drop_table("aauth_group_to_group", TRUE);
		### Drop table aauth_groups ##
		$this->dbforge->drop_table("aauth_groups", TRUE);
		### Drop table aauth_login_attempts ##
		$this->dbforge->drop_table("aauth_login_attempts", TRUE);
		### Drop table aauth_perm_to_group ##
		$this->dbforge->drop_table("aauth_perm_to_group", TRUE);
		### Drop table aauth_perm_to_user ##
		$this->dbforge->drop_table("aauth_perm_to_user", TRUE);
		### Drop table aauth_perms ##
		$this->dbforge->drop_table("aauth_perms", TRUE);
		### Drop table aauth_pms ##
		$this->dbforge->drop_table("aauth_pms", TRUE);
		### Drop table aauth_user_to_group ##
		$this->dbforge->drop_table("aauth_user_to_group", TRUE);
		### Drop table aauth_user_variables ##
		$this->dbforge->drop_table("aauth_user_variables", TRUE);
		### Drop table aauth_users ##
		$this->dbforge->drop_table("aauth_users", TRUE);

	}
}
