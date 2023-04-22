<?php
namespace noraziz\ci4aauth\Models;
 
use CodeIgniter\Model;
use noraziz\ci4aauth\Config\AauthConfig;

class AauthModel extends Model
{
    private $dbconn;
	private $config_vars;
	
	protected function initialize()
    {
		$this->config_vars = config('AauthConfig');
        $this->dbconn      = \Config\Database::connect();
    }
	
	
	
	
	/**
	 * ---------------------------------
	 * Pre-Cache
	 */
	public function get_precache_perms()
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_perms );
		$query   = $builder->get();
		return $query->getResult();
	}
	
	public function get_precache_groups()
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$query   = $builder->get();
		return $query->getResult();
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * LOGIN
	 */
	public function do_login_verified($db_identifier, $identifier, $is_strict= false, $flag_banned=null)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where($db_identifier, $identifier);
		
		if ($is_strict) {
			$builder->where('banned', 1);
			$builder->where('verification_code !=', '');
		}
		
		if ( isset($flag_banned) ) {
			$builder->where('banned', $flag_banned);
		}
		
		$query= $builder->get();
		return $query->getRow();
	}
	public function do_is_logged($cookie0, $cookie1)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $cookie0);
		$builder->where('remember_exp', $cookie1);
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_login_fast($user_id)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		$builder->where('banned', 0);
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_reset_login_attempts($curr_ipaddr)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_login_attempts );
		$builder->where(
			array(
				'ip_address'=>$curr_ipaddr,
				'timestamp >='=>date("Y-m-d H:i:s", strtotime("-".$this->config_vars->max_login_attempt_time_period))
			)
		);
		
		return $builder->delete();
	}
	
	public function do_update_verification_code_by_emailaddr($email, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('email', $email);
		
		return $builder->update($data_ext);
	}
	
	public function do_get_user_by_id($id, $arr_where=null)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $id);
		
		if( isset($arr_where) ) {
			$builder->where($arr_where);
		}
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_get_user_by_email($email)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('email', $email);
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_get_user_by_name($name)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('username', $name);
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_get_verification_code($ver_code)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('verification_code', $ver_code);
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_update_verification_code($user_id, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		
		return $builder->update($data_ext);
	}
	
	public function do_update_user_by_id($user_id, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		
		return $builder->update($data_ext);
	}
	
	public function do_update_last_login($user_id, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		
		return $builder->update($data_ext);
	}
	
	public function do_update_login_attempts($curr_ipaddr)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_login_attempts );
		$builder->where(
			array(
				'ip_address'=>$curr_ipaddr,
				'timestamp >='=>date("Y-m-d H:i:s", strtotime("-".$this->config_vars->max_login_attempt_time_period))
			)
		);
		$query = $builder->get();

		if($query->getNumRows() == 0){
			$data = array();
			$data['ip_address'] = $curr_ipaddr;
			$data['timestamp']= date("Y-m-d H:i:s");
			$data['login_attempts']= 1;
			
			$builder->insert($data);
			return true;
		}else{
			$row = $query->getRow();
			
			if (isset($row)) {
				$data = array();
				$data['timestamp'] = date("Y-m-d H:i:s");
				$data['login_attempts'] = $row->login_attempts + 1;
				
				$builder->where('id', $row->id);
				$builder->update($data);

				if ( $data['login_attempts'] > $this->config_vars->max_login_attempt ) {
					return false;
				} else {
					return true;
				}
			}
			
			return false;
		}
	}
	
	public function do_get_login_attempts($curr_ipaddr)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_login_attempts );
		$builder->where(
			array(
				'ip_address'=>$curr_ipaddr,
				'timestamp >='=>date("Y-m-d H:i:s", strtotime("-".$this->config_vars['max_login_attempt_time_period']))
			)
		);
		$query = $builder->get();

		if($query->getNumRows() != 0){
			$row = $query->getRow();
			
			if( isset($row) ) {
				return $row->login_attempts;
			}
		}

		return 0;
	}
	
	public function do_update_remember($user_id, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		
		return $builder->update($data_ext);
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * USER
	 */
	public function do_create_user($email, $pass, $username = false)
	{
		$data = array(
			'email' => $email,
			'pass' => $this->hash_password($pass, 0), // Password cannot be blank but user_id required for salt, setting bad password for now
			'username' => (!$username) ? '' : $username,
			'date_created' => date("Y-m-d H:i:s")
		);

		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		if ( $builder->insert($data) ){

			$user_id = $this->dbconn->insertID(); 

			// set default group
			$this->do_add_member($user_id, $this->config_vars->default_group);

			// if verification activated
			if($this->config_vars->verification && !$this->do_is_admin()){
				$data = null;
				$data['banned'] = 1;

				$builder = $this->dbconn->table( $this->config_vars->tbl_users );
				$builder->where('id', $user_id);
				$builder->update($data);
			}

			// Update to correct salted password
			if( !$this->config_vars->use_password_hash){
				$data = null;
				$data['pass'] = $this->hash_password($pass, $user_id);
				
				$builder = $this->dbconn->table( $this->config_vars->tbl_users );
				$builder->where('id', $user_id);
				$builder->update($$data);
			}

			return $user_id;

		} else {
			return false;
		}
	}
	
	public function do_list_users($group_par = false, $limit = false, $offset = false, $include_banneds = false, $sort = false)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->select('*');
		
		if ($group_par != false) {
			$builder->join($this->config_vars->tbl_user_to_group, $this->config_vars->tbl_users . ".id = " . $this->config_vars->tbl_user_to_group . ".user_id");
			$builder->where($this->config_vars->tbl_user_to_group . ".group_id", $group_par);
		}
		
		// banneds
		if (!$include_banneds) {
			$builder>where('banned != ', 1);
		}

		// order_by
		if ($sort) {
			$builder->orderBy($sort);
		}

		// limit
		if ($limit) {
			if ($offset == false)
				$builder->limit($limit);
			else
				$builder->limit($limit, $offset);
		}
	}
	
	public function do_delete_user($user_id)
	{
		$this->dbconn->transBegin();
		
		// delete from perm_to_user
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_user );
		$builder->where('user_id', $user_id);
		$builder->delete();

		// delete from user_to_group
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->where('user_id', $user_id);
		$builder->delete();

		// delete user vars
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		$builder->where('user_id', $user_id);
		$builder->delete();

		// delete user
		$builder= $this->dbconn->table( $this->config_vars->tbl_users );
		$builder->where('id', $user_id);
		$builder->delete();
		
		// finally
		if ($this->dbconn->transStatus() === false) {
			$this->dbconn->transRollback();
			return false;
		} else {
			$this->dbconn->transCommit();
			return true;
		}
	}
	
	public function do_send_verification($user_id)
	{
		return false;
	}
	
	public function do_is_admin()
	{
		return false;
	}
	
	
	/**
	 * ---------------------------------
	 * GROUP
	 */
	public function do_get_user_groups($user_id = false)
	{
		if( !$user_id){
			$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
			$builder->where('name', $this->config_vars->public_group);
		}else if($user_id){
			$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
			$builder->join($this->config_vars->tbl_groups, "id = group_id");
			$builder->where('user_id', $user_id);
		}
		
		$query= $builder->get();
		return $query->getResult();
	}
	
	public function do_get_user_on_groups($user_id, $group_id)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->where('user_id',$user_id);
		$builder->where('group_id',$group_id);
		
		$query= $builder->get();
		return $query->getResult();
	}
	
	public function get_user_perms( $user_id = false )
	{
		if($user_id){
			$builder = $this->dbconn->table( $this->config_vars->tbl_perm_to_user );
			
			$builder->select($this->config_vars->tbl_perms.'.*');
			$builder->where('user_id', $user_id);
			$builder->join($this->config_vars->tbl_perms, $this->config_vars->tbl_perms.'.id = '.$this->config_vars->tbl_perm_to_user.'.perm_id');
			
			$query= $builder->get();
			return $query->getResult();
		}
		
		return false;
	}
	
	public function do_create_group($group_name, $definition = '')
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('name', $group_name);
		$query= $builder->get();
		
		if($query->getNumRows() < 1){
			$data = array(
				'name' => $group_name,
				'definition'=> $definition
			);
			
			$builder->insert($data);
			$group_id = $this->dbconn->insertID();
			
			return $group_id;
		}

		return false;
	}
	
	public function do_update_group_by_id($group_id, $data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('id', $group_id);
		
		return $builder->update($data_ext);
	}
	
	public function do_get_group_by_id($group_id, $arr_where=null)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('id', $group_id);
		
		if( isset($arr_where) ) {
			$builder->where($arr_where);
		}
		
		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_delete_group($group_id)
	{
		$this->dbconn->transBegin();
		
		// bug fixed
		// now users are deleted from user_to_group table
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->where('group_id', $group_id);
		$builder->delete();

		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->where('group_id', $group_id);
		$builder->delete();

		$builder= $this->dbconn->table( $this->config_vars->tbl_group_to_group );
		$builder->where('group_id', $group_id);
		$builder->delete();

		$builder= $this->dbconn->table( $this->config_vars->tbl_group_to_group );
		$builder->where('subgroup_id', $group_id);
		$builder->delete();
		
		$builder= $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('id', $group_id);
		$builder->delete();
		
		// finally
		if ($this->dbconn->transStatus() === false) {
			$this->dbconn->transRollback();
			return false;
		} else {
			$this->dbconn->transCommit();
			return true;
		}
	}
	
	public function do_add_member($data_ext)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->insert($data_ext);
		$group_id = $this->dbconn->insertID();
		
		return $group_id;
	}
	
	public function do_remove_member($user_id, $group_par)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->where('user_id', $user_id);
		$builder->where('group_id', $group_par);
		return $builder->delete();
	}
	
	public function do_add_subgroup($group_id, $subgroup_id)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_group_to_group );
		
		$builder->where('group_id',$group_id);
		$builder->where('subgroup_id',$subgroup_id);
		$query = $builder->get();

		if($query->getNumRows() < 1){
			$data = array(
				'group_id' => $group_id,
				'subgroup_id' => $subgroup_id,
			);

			return $builder->insert($data);
		}
		
		return true;
	}
	
	public function do_remove_subgroup($group_par, $subgroup_par)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_group_to_group );
		
		$builder->where('group_id', $group_par);
		$builder->where('subgroup_id', $subgroup_par);
		return $builder->delete();
	}
	
	public function do_remove_member_from_all($user_id)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		
		$builder->where('user_id', $user_id);
		return $builder->delete($this->config_vars->user_to_group);
	}
	
	public function do_is_member( $group_ids, $user_id = false )
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_user_to_group );
		$builder->where('user_id', $user_id);
		
		if(count($group_ids) > 1){
			foreach ($groups_ids as $group_id) {
				$builder->or_where('group_id', $group_id);
			}
		} else {
			$builder->where('group_id', $group_ids);
		}
		
		$query= $builder->get();
		if ($query->getNumRows() > 0) {
			return true;
		} else {
			return false;
		}
	}
	
	public function do_list_groups()
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		
		$query= $builder->get();
		return $query->getResult();
	}
	
	public function do_get_group_name($group_id)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('id', $group_id);
		$query= $builder->get();

		if ($query->getNumRows() == 0)
			return false;

		$row = $query->getRow();
		return $row->name;
	}
	
	public function do_get_group ( $group_id )
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_groups );
		$builder->where('id', $group_id);
		$query = $builder->get();

		$query= $builder->get();
		return $query->getRow();
	}
	
	public function do_get_group_perms ( $group_id )
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->select($this->config_vars->perms.'.*');
		$builder->where('group_id', $group_id);
		$builder->join($this->config_vars->tbl_perms, $this->config_vars->tbl_perms.'.id = '.$this->config_vars->tbl_perm_to_group.'.perm_id');
		
		$query= $builder->get();
		return $query->getResult();
	}
	
	public function do_get_subgroups ( $group_id )
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_perm_to_group );

		$builder->where('group_id', $group_id);
		$builder->select('subgroup_id');
		$query= $builder->get();

		if ($query->getNumRows() == 0)
			return false;

		return $query->getResult();
	}
	
	public function do_delete_perm($perm_id)
	{
		$this->dbconn->transBegin();
		
		// deletes from perm_to_gropup table
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->where('perm_id', $perm_id);
		$builder->delete();

		// deletes from perm_to_user table
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_perm_to_userp );
		$builder->where('perm_id', $perm_id);
		$builder->delete();

		// deletes from permission table
		$builder= $this->dbconn->table( $this->config_vars->tbl_perms );
		$builder->where('id', $perm_id);
		$builder->delete();
		
		// finally
		if ($this->dbconn->transStatus() === false) {
			$this->dbconn->transRollback();
			return false;
		} else {
			$this->dbconn->transCommit();
			return true;
		}
	}
	
	public function do_list_group_perms($group_par)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perms );
		
		$builder->select('*');
		$builder->join($this->config_vars->tbl_perm_to_group, "perm_id = ".$this->config_vars->tbl_perms.".id");
		$builder->where($this->config_vars->tbl_perm_to_group.'.group_id', $group_par);

		$query = $builder->get();
		if ($query->getNumRows() == 0)
			return false;

		return $query->getResult();
	}
	
	public function do_is_allowed($perm_id, $user_id=false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_user );
		
		$builder->where('perm_id', $perm_id);
		$builder->where('user_id', $user_id);
		$query = $builder->get();

		if( $query->getNumRows() > 0){
			return true;
		}
		
		return false;
	}
	
	public function do_is_group_allowed($perm_id, $group_par=false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->where('perm_id', $perm_id);
		$builder->where('group_id', $group_par);
		$query = $builder->get();
		
		if( $query->getNumRows() > 0){
			return true;
		}
		
		return false;
	}
	
	public function do_allow_user($user_id, $perm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_user );
		$builder->where('user_id',$user_id);
		$builder->where('perm_id',$perm_id);
		$query = $builder->get();
		
		if ($query->getNumRows() < 1) {
			$data = array(
				'user_id' => $user_id,
				'perm_id' => $perm_id
			);
			
			return $builder->insert($data);	
		}
		
		return false;
	}
	
	public function do_deny_user($user_id, $perm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_user );
		$builder->where('user_id', $user_id);
		$builder->where('perm_id', $perm_id);
		
		return $builder->delete();
	}
	
	public function do_allow_group($group_id, $perm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->where('group_id',$group_id);
		$builder->where('perm_id',$perm_id);
		$query = $builder->get();
		
		if ($query->getNumRows() < 1) {
			$data = array(
				'group_id' => $group_id,
				'perm_id' => $perm_id
			);
			
			return $builder->insert($data);	
		}
		
		return false;
	}
	
	public function do_deny_group($group_id, $perm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm_to_group );
		$builder->where('group_id', $group_id);
		$builder->where('perm_id', $perm_id);
		
		return $builder->delete();
	}
	
	public function do_list_perms()
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm );
		$query = $builder->get();
		
		if ($query->getNumRows() == 0)
			return false;

		return $query->getResult();
	}
	
	public function do_get_perm($perm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_perm );
		$builder->where('id', $perm_id);
		$query = $builder->get();
		
		if ($query->getNumRows() > 0)
			return $query->getRow();
		
		return false;
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * MESSAGING
	 */
	public function do_send_pm( $sender_id, $receiver_id, $title, $message )
	{
		$data = array(
			'sender_id' => $sender_id,
			'receiver_id' => $receiver_id,
			'title' => $title,
			'message' => $message,
			'date_sent' => date('Y-m-d H:i:s')
		);
		
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		return $builder->insert($data );
	}
	
	public function do_list_pms($limit=5, $offset=0, $receiver_id=null, $sender_id=null)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		
		if (is_numeric($receiver_id)){
			$builder->where('receiver_id', $receiver_id);
			$builder->where('pm_deleted_receiver', null);
		}
		if (is_numeric($sender_id)){
			$builder->where('sender_id', $sender_id);
			$builder->where('pm_deleted_sender', null);
		}

		$builder->orderBy('id','DESC');
		$query = $builder->get();

		if ($query->getNumRows() > 0)
			return $query->getResult();
		
		return false;
	}
	
	public function do_get_pm($pm_id, $user_id = null, $set_as_read = true)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		
		$builder->where('id', $pm_id);
		$builder->groupStart();
		$builder->where('receiver_id', $user_id);
		$builder->orWhere('sender_id', $user_id);
		$builder->groupEnd();
		$query = $builder->get( $this->config_vars->pms );

		if ($query->getNumRows() > 0)
			return $query->getRow();
		
		return false;
	}
	
	public function do_delete_pm($pm_id, $user_id = null)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		
		$builder->where('id', $pm_id);
		$builder->groupStart();
		$builder->where('receiver_id', $user_id);
		$builder->orWhere('sender_id', $user_id);
		$builder->groupEnd();
		$query = $builder->get();
		
		$res_pm = $query->row();
		
		if ($res_pm->getNumRows() > 0) {
			if ($user_id == $res_pm->sender_id){
				if($res_pm->pm_deleted_receiver == 1){
					return $builder->delete( array('id' => $pm_id) );
				}
				
				$builder->set('pm_deleted_sender', 1);
				$builder->where('id', $pm_id);
				return $builder->update();
			}else if ($user_id == $res_pm->receiver_id){
				if($res_pm->pm_deleted_sender == 1){
					return $builder->delete( array('id' => $pm_id) );
				}
				
				$builder->set('pm_deleted_receiver', 1);
				$builder->set('date_read', date('Y-m-d H:i:s'));
				$builder->where('id', $pm_id);
				return $this->aauth_db->update();
			}
		}
		return false;
	}
	
	public function do_cleanup_pms($date_sent)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		$builder->where('date_sent <', $date_sent);
		
		return $builder->delete();
	}
	
	public function do_count_unread_pms($receiver_id=false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		
		$builder->where('receiver_id', $receiver_id);
		$builder->where('date_read', null);
		$builderb->where('pm_deleted_sender', null);
		$builder->where('pm_deleted_receiver', null);
		$query = $builder->get();

		return $query->getNumRows();
	}
	
	public function do_set_as_read_pm($pm_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_pms );
		
		$builder->set('date_read', date('Y-m-d H:i:s'));
		$builder->where('id', $pm_id);
		$builder->update();
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * USER VARIABLES
	 */
	public function do_set_user_var( $key, $value, $user_id, $is_insert_mode=false )
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		
		if ($is_insert_mode ===false) {

			$data = array(
				'data_key' => $key,
				'value' => $value,
				'user_id' => $user_id
			);

			return $builder->insert( $data );
		}
		// if var already set, overwrite
		else {

			$data = array(
				'data_key' => $key,
				'value' => $value,
				'user_id' => $user_id
			);

			$builder->set( 'value', $value );
			$builder->where( 'data_key', $key );
			$builder->where( 'user_id', $user_id);

			return $builder->update();
		}
	}
	
	public function do_unset_user_var( $key, $user_id = false )
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		
		$builder->where('data_key', $key);
		$builder->where('user_id', $user_id);

		return $builder->delete();
	}
	
	public function do_get_user_var( $key, $user_id = false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		
		$builder->where('user_id', $user_id);
		$builder->where('data_key', $key);
		$query = $builder->get();

		// if variable not set
		if ($query->getNumRows() < 1) {
			return false;
		}
		else {
			$row = $query->getRow();
			return $row->value;
		}
	}
	
	public function do_get_user_vars( $user_id = false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		
		$builder->select('data_key, value');
		$builder->where('user_id', $user_id);
		$query = $builder->get();

		return $query->getResult();
	}
	
	public function do_list_user_var_keys($user_id = false)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_user_variables );
		
		$builder->select('data_key');
		$qbuilder->where('user_id', $user_id);
		$query = $builder->get();

		// if variable not set
		if ($query->getNumRows() < 1) { 
			return false;
		}
		else {
			return $query->getResult();
		}
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * re-CAPTCHA
	 */
	public function do_update_user_totp_secret($user_id, $secret)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_users );
		
		$builder->set('totp_secret', $secret);
		$builder->where('id', $user_id);
		return $builder->update();
	}
	
	public function get_user_totp_secret($secret)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_users );
		
		$builder->where('totp_secret', $secret);
		$query = $builder->get();
		
		if ($query->getNumRows() == 0) { 
			return true;
		}
		return false;
	}
	
	public function get_user_totp_code($user_id)
	{
		$builder= $this->dbconn->table( $this->config_vars->tbl_users );
		
		$builder->where('id', $user_id);
		$query = $builder->get();
		
		if ($query->getNumRows() == 0) { 
			return $query->getRow()->totp_secret;
		}
		return false;
	}
	
	
	
	
	/**
	 * ---------------------------------
	 * PERMISSION
	 */
	public function do_create_perm($perm_name, $definition='')
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_perms );
		$builder->where('name', $perm_name);
		$query= $builder->get();
		
		if($query->getNumRows() < 1){
			$data = array(
				'name' => $perm_name,
				'definition'=> $definition
			);
			
			$builder->insert($data);
			$perm_id = $this->dbconn->insertID();
			
			return $perm_id;
		}

		return false;
	}
	
	public function do_update_perm($perm_id, $data)
	{
		$builder = $this->dbconn->table( $this->config_vars->tbl_perms );
		$builder->where('id', $perm_id);
		
		return $builder->update($data);
	}
	
	
	
	
	
	
	/**
	 * ---------------------------------
	 * MISC
	 */
	 
	/**
	 * Hash password
	 * Hash the password for storage in the database
	 * (thanks to Jacob Tomlinson for contribution)
	 * @param string $pass Password to hash
	 * @param $userid
	 * @return string Hashed password
	 */
	public function hash_password($pass, $userid)
	{
		if($this->config_vars->use_password_hash){
			return password_hash($pass, $this->config_vars->password_hash_algo, $this->config_vars->password_hash_options);
		} else {
			$salt = md5($userid);
			return hash($this->config_vars->hash_type, $salt.$pass);
		}
	}
	
	
	/**
	 * ---------------------------------
	 * Testing
	 */
	public function getData()
    {
        print_r($this->config_vars->tbl_perms);
		return 'Ini adalah Method getData didalam ProductModel';
    }
}
