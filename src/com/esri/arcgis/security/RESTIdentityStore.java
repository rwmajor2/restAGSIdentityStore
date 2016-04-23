package com.esri.arcgis.security;

import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.esri.arcgis.discovery.admin.security.AGSSecurityException;
import com.esri.arcgis.discovery.admin.security.Role;
import com.esri.arcgis.discovery.admin.security.RoleStore;
import com.esri.arcgis.discovery.admin.security.User;
import com.esri.arcgis.discovery.admin.security.UserStore;
import com.esri.arcgis.interop.AutomationException;
import com.esri.arcgis.system.ILog;
import com.esri.arcgis.system.ServerUtilities;


public class RESTIdentityStore implements UserStore, RoleStore {
	final String STOREPATH = "StorePath";

	private String pathToStore = null;
	private Document xmlFileStore = null;
	private NodeList userList = null;
	private NodeList roleList = null;
	private NodeList userRolesList = null;

	/* FileStore XML elements */
	private static final String USERS = "users";
	private static final String USER = "user";
	private static final String ROLES = "roles";
	private static final String ROLE = "role";
	private static final String USER_ROLES = "user_roles";
	
	private ILog serverLog;

	/**
	 * Add a new role to the identity store.
	 * @param role a role object containing information about the role
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void addRole(Role role) throws AGSSecurityException {

		String rolename = role.getRolename();

		readFromStore();
		// Check if the role exists
		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element roleElement = (Element) roleList.item(i);
			if (rolename.equalsIgnoreCase(roleElement.getAttribute("name"))) {
				throw new AGSSecurityException("The specified Role already exists in file store");
			}
		}

		// Role does not exist, create a new element and append to node
		Node rolesNode = xmlFileStore.getElementsByTagName(ROLES).item(0);
		Element newRoleElem = xmlFileStore.createElement(ROLE);
		newRoleElem.setAttribute("name", rolename);
		newRoleElem.setAttribute("description", role.getDescription());
		rolesNode.appendChild(newRoleElem);

		writeToStore();
	}

	/**
	 * Assign a role to a group of users.
	 * @param rolename the name of the role
	 * @param usernames a list of user accounts that need to be assigned this role
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */	
	public void addUsersToRole(String rolename, List<String> usernames) throws AGSSecurityException {

		readFromStore();
		
		Element userRoleElement = (Element) xmlFileStore.getElementsByTagName(USER_ROLES).item(0);

		for (String userName : usernames) {
			Element entry = xmlFileStore.createElement(userName);
			entry.setTextContent(rolename);
			userRoleElement.appendChild(entry);
		}

		writeToStore();
	}

	/**
	 * Assign a list of roles to a user. The roles and user must previously exist in the identity
	 * store.
	 * @param username the name of the user for whom the roles are to be assigned
	 * @param roles a list of roles to be assigned
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void assignRoles(String username, List<String> roles) throws AGSSecurityException {

		readFromStore();

		Element userRoleElement = (Element) xmlFileStore.getElementsByTagName(USER_ROLES).item(0);

		// Create a new element for each role and append it to userRoleElement
		for (int i = 0 ; i < roles.size(); i++) {
			Element entry = xmlFileStore.createElement(username);
			entry.setTextContent(roles.get(i));
			userRoleElement.appendChild(entry);
		}

		writeToStore();
	}

	/**
	 * Deletes a role from the identity store.
	 * @param rolename the name of the role to delete
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void deleteRole(String roleName) throws AGSSecurityException {

		readFromStore();

		// Delete if the role exists
		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element roleElement = (Element) roleList.item(i);
			if (roleName.equalsIgnoreCase(roleElement.getAttribute("name"))) {
				xmlFileStore.getElementsByTagName(ROLES).item(0).removeChild(roleElement);
			}
		}

		// Clean up all the user-role mappings for this role
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		for (int i = 0; i < userRolesList.getLength(); i++) {
			if (userRolesList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element userElem = (Element) userRolesList.item(i);
			String currentRoleName = userElem.getTextContent();
			if (currentRoleName.equalsIgnoreCase(roleName)) {
				xmlFileStore.getElementsByTagName(USER_ROLES).item(0).removeChild(userElem);
			}
		}

		writeToStore();
	}

	/**
	 * Populates the input list with role information up to the maxCount parameter
	 * and filtered by the filter string.
	 * @param roles A non null list that will be populated by the resultant roles
	 * @param filter a filter string to narrow down the search query
	 * @param maxCount the maximum number of roles that the client expects
	 * @return true if there are more roles than what is returned by the query, false otherwise
	 * @throws IllegalArgumentException if the roles parameter is null
	 * @throws AGSSecurityException If the operation could be completed successfully.
	 */
	public boolean getAllRoles(List<Role> roles, String filter, int maxCount) throws IllegalArgumentException, AGSSecurityException {


		if (maxCount < 1)
			maxCount = 1000;

		boolean moreRoles = false;

		readFromStore();
		roleList = xmlFileStore.getElementsByTagName(ROLES).item(0).getChildNodes();

		int numResults = 0;
		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			if( numResults == maxCount) {
				moreRoles = true;
				break;
			}
			Element roleElement = (Element)roleList.item(i);
			String roleName = roleElement.getAttribute("name");
			Role role = new Role(roleName);
			role.setDescription(roleElement.getAttribute("description"));
			if( filter == null || filter == "" ) {
				roles.add(role);
				numResults++;
			} else if ( roleName.contains(filter)) {
				roles.add(role);
				numResults++;
			}
		}		
		return moreRoles;
	}

	/**
	 * Populates the input list with role information that fall in the given page
	 * range.
	 * If you have a total of 20 roles, then pageNumber of 2 and pageSize of 5
	 * will return roles from 6 to 10.
	 * @param roles A non null list that will be populated by the resultant roles
	 * @param startIndex the starting position from which to return the results. startIndex is zero-based.
	 * @param pageSize the size of the page of results to return. 
	 * @throws IllegalArgumentException if the roles parameter is null
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public boolean getAllRoles(List<Role> roles, int startIndex, int pageSize) throws IllegalArgumentException, AGSSecurityException {

		boolean moreRoles = false;

		readFromStore();
		roleList = xmlFileStore.getElementsByTagName(ROLES).item(0).getChildNodes();

		int rowIndex = 0;
		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			if( !(rowIndex < (startIndex+pageSize)) )
				break;
			if (rowIndex >= startIndex ) {
				Element roleElement = (Element)roleList.item(i);			
				Role role = new Role(roleElement.getAttribute("name"));
				role.setDescription(roleElement.getAttribute("description"));
				roles.add(role);
			}
			rowIndex++;
		}		
		if( rowIndex < getTotalRoles())
			moreRoles = true;
		return moreRoles;
	}

	/**
	 * Returns a role information given the role name.
	 * @param rolename the name of the role
	 * @return a Role object representing the role stored in the identity store.
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public Role getRole(String rolename) throws AGSSecurityException {

		List<Role> roles = new ArrayList<Role>(); 
		getAllRoles(roles, rolename, 1);
		return roles.get(0);
	}

	/**
	 * Populates the input rolenames parameter with a list of role names that have been
	 * assigned to this user that satisfy the filter criteria upto a maximum number indicated
	 * by the maxCount parameter.
	 * @param username the name of the user from whom to return the roles
	 * @param rolenames an input list of String that will be populated by role names
	 * @param filter an optional parameter used to filter the result 
	 * @param maxCount an optional parameter that indicates the number of results the client
	 *                 is willing to accept
	 * @return true if there are more results than what is returned, false otherwise
	 * @throws IllegalArgumentException If the rolenames parameter is null
	 * @throws AGSSecurityException If the operation could not be completed.
	 */
	public boolean getRolesForUser(String username, List<String> rolenames, String filter, int maxCount) throws IllegalArgumentException, AGSSecurityException {

		if (maxCount < 1)
			maxCount = 1;
		boolean moreResults = false;		
		
		return moreResults;
	}

	/**
	 * Returns the total number of roles in the identity store.
	 * @return the total roles in the store.
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public long getTotalRoles() throws AGSSecurityException {

		readFromStore();
		roleList = xmlFileStore.getElementsByTagName(ROLES).item(0).getChildNodes();

		int totalRoles = 0;
		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			totalRoles++;
		}
		return totalRoles;
	}

	/**
	 * Populates the input usernames parameter with a list of user names that have been
	 * assigned this role that satisfy the filter criteria upto a maximum number indicated
	 * by the maxCount parameter.
	 * @param rolename the name of the role assigned to the users
	 * @param usernames an input list of String that will be populated with user names
	 * @param filter an optional parameter used to filter the result 
	 * @param maxCount an optional parameter that indicates the number of results the client
	 *                 is willing to accept
	 * @return true if there are more results than what is returned, false otherwise
	 * @throws IllegalArgumentException If the usernames parameter is null
	 * @throws AGSSecurityException If the operation could not be completed.
	 */
	public boolean getUsersWithinRole(String roleName, List<String> userNames, String filter, int maxCount) 
	throws IllegalArgumentException, AGSSecurityException {

		if (maxCount < 1)
			maxCount = 1;

		readFromStore();
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		boolean moreResults = false;		

		// Loop through all the user-role elements and find if a user has this role
		int numResults = 0;
		for (int i = 0; i < userRolesList.getLength(); i++) {
			if (userRolesList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			if (numResults == maxCount) {
				moreResults = true;
				break;
			}
			Element userElem = (Element) userRolesList.item(i);
			String currentRoleName = userElem.getTextContent();
			String userName = userElem.getNodeName();
			if (currentRoleName.equalsIgnoreCase(roleName)) {
				if (filter != null && filter != ""){
					if(userName.contains(filter)) {
						userNames.add(userName);
						numResults++;
					}
				} else {
					userNames.add(userName);
					numResults++;
				}
			}
		}
		return moreResults;
	}

	/**
	 * Remove assigned roles from a specific user account. The user must previously exist
	 * in the identity store.
	 * @param username the name of the user from whom the roles are to be removed
	 * @param roles list of roles to be removed
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void removeRoles(String username, List<String> roles) throws AGSSecurityException {

		readFromStore();
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		// Loop through all the user-role elements and find if a user has this role

		for (int i = 0; i < userRolesList.getLength(); i++) {
			if (userRolesList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;

			Element userElem = (Element) userRolesList.item(i);
			String userName = userElem.getNodeName();
			if (userName.equalsIgnoreCase(username) ) {
				String roleName = userElem.getTextContent();
				for(int x = 0 ; x < roles.size() ; x++) 
					if( roles.get(x).equalsIgnoreCase(roleName) )
						xmlFileStore.getElementsByTagName(USER_ROLES).item(0).removeChild(userElem);
			}
		}
		writeToStore();
	}

	/**
	 * Removes the role assignment from a list of user accounts.
	 * @param rolename the name of the role
	 * @param usernames the list of user accounts from whom the role assignment must be removed
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void removeUsersFromRole(String rolename, List<String> usernames) throws AGSSecurityException {

		readFromStore();
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		// Loop through all the user-role elements and find if a user has this role

		for (int i = 0; i < userRolesList.getLength(); i++) {
			if (userRolesList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;

			Element userElem = (Element) userRolesList.item(i);
			String userName = userElem.getNodeName();
			String roleName = userElem.getTextContent();

			if (rolename.equalsIgnoreCase(roleName) ) {
				for(int x = 0 ; x < usernames.size() ; x++) 
					if( usernames.get(x).equalsIgnoreCase(userName) )
						xmlFileStore.getElementsByTagName(USER_ROLES).item(0).removeChild(userElem);
			}
		}
		writeToStore();

	}

	/**
	 * Updates the existing role with new description.
	 * @param role updated role information 
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void updateRole(Role role) throws AGSSecurityException {

		readFromStore();
		roleList = xmlFileStore.getElementsByTagName(ROLES).item(0).getChildNodes();

		String roleToUpdate = role.getRolename() ;		
		String newDescription = role.getDescription();

		for (int i = 0; i < roleList.getLength(); i++) {
			if (roleList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;

			Element roleElement = (Element)roleList.item(i);
			String roleName = roleElement.getAttribute("name");

			if( roleName.equalsIgnoreCase( roleToUpdate) ) 
				roleElement.setAttribute("description", newDescription);

		}
		writeToStore();
	}

	/**
	 * Adds a new user account to the identity store.
	 * @param user a new user account object
	 * @throws AGSSecurityExceptionIf the operation could not be completed successfully.
	 */
	public void addUser(User user) throws AGSSecurityException {

		String username = user.getUsername();		

		readFromStore();
		
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		// Check if the user exists in the store
		for (int i = 0; i < userList.getLength(); i++) {
			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element userElement = (Element) userList.item(i);
			if (username.equalsIgnoreCase(userElement.getAttribute("name"))) {
				throw new AGSSecurityException("The specified user already exists in the store");
			}
		}

		// User does not exist, create a new element and append to node
		Node usersNode = xmlFileStore.getElementsByTagName(USERS).item(0);
		Element newUserElem = xmlFileStore.createElement(USER);
		newUserElem.setAttribute("name", username);
		newUserElem.setAttribute("fullname", user.getFullname());		
		newUserElem.setAttribute("password", user.getPassword());
		newUserElem.setAttribute("e-mail", user.getEmail());
		newUserElem.setAttribute("description", user.getDescription());
		usersNode.appendChild(newUserElem);

		// Update the file store
		writeToStore();
	}

	  /**
	   * Changes the password on a user account.
	   * @param username the name of the user
	   * @param oldPassword the old password on the account
	   * @param newPassword the new password on the account
	   * @throws AGSSecurityException If the operation could not be completed successfully
	   */
	  public void changePassword(String username, String oldPassword, String newPassword) throws AGSSecurityException {

			readFromStore();
			userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

			for (int i = 0; i < userList.getLength(); i++) {

				if (userList.item(i).getNodeType() == Node.TEXT_NODE)
					continue;

				Element userElement = (Element) userList.item(i);
				String userName = userElement.getAttribute("name");
				String currPass = userElement.getAttribute("password");

				if (username.equalsIgnoreCase(userName) ) {
					if( oldPassword.equalsIgnoreCase(currPass))
						userElement.setAttribute("password", newPassword);
					else
						throw new AGSSecurityException("Current Password does not match.");
				}
			}
			writeToStore();
		  
	  }

	  /**
	   * Changes the secret question on a user account.
	   * @param username the name of the user
	   * @param password the password for the user
	   * @param secretQuestion the new secret question
	   * @param secretAnswer answer for the secret question
	   * @throws AGSSecurityException If the operation could not be completed successfully
	   */
	  public void changeSecretQuestion(String username, String password, String secretQuestion, String secretAnswer) throws AGSSecurityException {
		  // Not implementing this method.
	  }	  

	  /**
	   * Decrypt the properties that are read from the configuration store.
	   * @param props properties read from the configuration store
	   * @return the same bag of properties where the password fields are decrypted
	   * @throws AGSSecurityException If the operation could not be completed successfully.
	   */
	public Map<String, String> decrypt(Map<String, String> props)
			throws AGSSecurityException {
		  // No properties will be encrypted\decrypted.
		return props;
	}

	/**
	 * Delete the user account from the identity store.
	 * @param username the name of the user to delete
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void deleteUser(String userName) throws AGSSecurityException {

		readFromStore();

		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		for (int i = 0; i < userList.getLength(); i++) {
			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element userElement = (Element) userList.item(i);
			if (userName.equalsIgnoreCase(userElement.getAttribute("name"))) {
				xmlFileStore.getElementsByTagName(USERS).item(0).removeChild(userElement);
			}
		}

		// Clean up all user-role mappings for this user
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		for (int i = 0; i < userRolesList.getLength(); i++) {
			if (userRolesList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			Element userElem = (Element)userRolesList.item(i);
			if ( userElem.getNodeName().equalsIgnoreCase(userName) )				
				xmlFileStore.getElementsByTagName(USER_ROLES).item(0).removeChild(userElem);
		}

		writeToStore();
	}

	  /**
	   * Encrypt the user defined properties for storage to disk.
	   * @param props plain text properties entered by the user through the user interface
	   * @return the same bag of properties where the password fields are encrypted
	   * @throws AGSSecurityException If the operation could not be completed successfully.
	   */
	  public Map<String,String> encrypt(Map<String,String> props) throws AGSSecurityException {	  
		  // No properties will be encrypted.
		  return props;
	  }

	/**
	 * Populates the input list with users account information upto a maximum number
	 * and filtered by the filter string.
	 * @param users A non null list that will be populated by the resultant user accounts
	 * @param filter a filter string to narrow down the search query
	 * @param maxCount the maximum number of users that the client expects
	 * @return true if there are more users than what is returned by the query, false otherwise
	 * @throws IllegalArgumentException if the users parameter is null
	 * @throws AGSSecurityException If the operation could be completed successfully.
	 */
	public boolean getAllUsers(List<User> users, String filter, int maxCount)	throws IllegalArgumentException, AGSSecurityException {

		if (maxCount < 1)
			maxCount = 1000;

		boolean moreUsers = false;

		readFromStore();

		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		int numResults = 0;
		for (int i = 0; i < userList.getLength(); i++) {
			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			if( numResults == maxCount) {
				moreUsers = true;
				break;
			}
			Element userElement = (Element) userList.item(i);
			String userName = userElement.getAttribute("name");
			User user = new User(userName);
			user.setDescription(userElement.getAttribute("description"));
			user.setFullname(userElement.getAttribute("fullname"));
			user.setEmail(userElement.getAttribute("e-mail"));			
			if( filter == null || filter == "" ) {
				users.add(user);
				numResults++;
			} else if (userName.contains(filter)) {
				users.add(user);
				numResults++;
			}
		}

		return moreUsers;
	}

	/**
	 * Populates the input list with user account information that fall in the given page
	 * range.
	 * If you have a total of 20 users, then pageNumber of 2 and pageSize of 5
	 * will return users from 6 to 10.
	 * @param users A non null list that will be populated by the resultant user accounts
	 * @param startIndex the starting position from which to return the results. startIndex is zero-based.
	 * @param pageSize the size of the page of results to return. 
	 * @return true if there are more users than what is returned by the query, false otherwise
	 * @throws IllegalArgumentException if the users parameter is null
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public boolean getAllUsers(List<User> users, int startIndex, int pageSize)	throws IllegalArgumentException, AGSSecurityException {

		boolean moreUsers = false;

		readFromStore();
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		int rowIndex = 0;
		for (int i = 0; i < userList.getLength(); i++) {
			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			if( !(rowIndex < (startIndex+pageSize)) )
				break;
			if (rowIndex >= startIndex ) {
				Element userElement = (Element)userList.item(i);			
				User user = new User(userElement.getAttribute("name"));
				user.setDescription(userElement.getAttribute("description"));
				user.setFullname(userElement.getAttribute("fullname"));
				user.setEmail(userElement.getAttribute("e-mail"));			
				users.add(user);
			}
			rowIndex++;
		}		
		if( rowIndex < getTotalUsers())
			moreUsers = true;
		return moreUsers;
	}

	/**
	 * Returns the total number of user accounts present in the identity store.
	 * @return the total number of user accounts
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public long getTotalUsers() throws AGSSecurityException {

		readFromStore();
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		int totalUsers = 0;
		for (int i = 0; i < userList.getLength(); i++) {
			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;
			totalUsers++;
		}		
		return totalUsers;
	}

	/**
	 * Returns the account information for a specific user.
	 * @param username the name of the user
	 * @return a User object representing the user account
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public User getUser(String username) throws AGSSecurityException {

		List<User> users = new ArrayList<User>();
		getAllUsers(users, username, 1);
		return users.get(0);		
	}

	/**
	 * Initialize the implementation with a set of properties.
	 * @param props a map of prop
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void initialize(Map<String, String> storeProperties) throws AGSSecurityException {
		
		this.serverLog = ServerUtilities.getServerLogger();
		
		try {
			serverLog.addMessage(3, 200, "Custom Identity Store Initiliazed....");
		} catch (AutomationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		if(storeProperties == null)
			throw new AGSSecurityException("Required argument storeProperties is null");
		
		pathToStore = storeProperties.get(STOREPATH);
		
		if (pathToStore == null)
			throw new AGSSecurityException("File store location was not specified");

		// Check if the file exists
		File file = new File(pathToStore);

		if (!file.exists() || file.length() == 0) {

			// File does not exist, create it			
			FileOutputStream outFileStream = null;
			try {
				DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
				Document fileStore = docBuilder.newDocument();

				// Create required elements
				Element rootElement = fileStore.createElement("FileStore");
				Element usersElement = fileStore.createElement(USERS);
				Element rolesElement = fileStore.createElement(ROLES);
				Element userRoleElement = fileStore.createElement(USER_ROLES);

				rootElement.appendChild(usersElement);
				rootElement.appendChild(rolesElement);
				rootElement.appendChild(userRoleElement);

				// Append the elements to the document
				fileStore.appendChild(rootElement);

				// Write the document to file
				Transformer xformer = TransformerFactory.newInstance().newTransformer();
				outFileStream = new FileOutputStream(pathToStore);
				Result result = new StreamResult(outFileStream);
				xformer.transform((Source) new DOMSource(fileStore), result);
				outFileStream.close();				

			} catch (Exception e) {
				throw new AGSSecurityException("Could not create the file store", e);
			}
		}
	}	// End initialize

	/**
	 * Test if a given identity store can be written to. If the identity store
	 * is a read-only store then no add/update/delete operations must be performed
	 * on it.
	 * @return true if the identity store is a read only store, false otherwise.
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public boolean isReadOnly() throws AGSSecurityException {
		// Set to false to allow Server Manager to add, update & delete users & roles.
		return true;
	}

	  /**
	   * Resets the password of the user account to a new automatically generated password.
	   * @param username the name of the user for whom to reset the password
	   * @param secretAnswer the answer to the secret question.
	   * @return the automatically generated new password
	   * @throws AGSSecurityException If the operation could not be completed successfully.
	   */
	  public String resetPassword(String username, String secretAnswer) throws AGSSecurityException {
		  // Not implementing this method
		  return "";
	  }
	/**
	 * Tests a connection to the identity store. The implementation of this method
	 * must not cache the input map of properties. 
	 * @param props the connection properties to a specific identity store
	 * @return true if the connection is successful, false otherwise
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public boolean testConnection(Map<String, String> props) throws AGSSecurityException {

		if(props == null)
			throw new AGSSecurityException("Map<String, String> storeProperties is null");
		
		return true;
	}

	/**
	 * Updates an existing user account with new information.
	 * @param user updated user account
	 * @throws AGSSecurityException If the operation could not be completed successfully.
	 */
	public void updateUser(User user) throws AGSSecurityException {

		String userToUpdate = user.getUsername();
		String newEmail = user.getEmail();
		String newDesc = user.getDescription();
		String newFullName = user.getFullname();

		readFromStore();
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		for (int i = 0; i < userList.getLength(); i++) {

			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;

			Element userElement = (Element) userList.item(i);
			String userName = userElement.getAttribute("name");

			if (userToUpdate.equalsIgnoreCase(userName)) {
				userElement.setAttribute("description", newDesc);
				userElement.setAttribute("fullname", newFullName);
				userElement.setAttribute("e-mail", newEmail);
			}
		}
		writeToStore();
	}

	/**
	 * Verifies that the specified user and password exist in the identity store.
	 * @param username
	 * @param password
	 * @return
	 * @throws AGSSecurityException
	 */
	public boolean validateUser(String username, String password) throws AGSSecurityException {

		boolean validUser = false;
		readFromStore();
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();

		for (int i = 0; i < userList.getLength(); i++) {

			if (userList.item(i).getNodeType() == Node.TEXT_NODE)
				continue;

			Element user = (Element) userList.item(i);
			if (username.equalsIgnoreCase(user.getAttribute("name"))) {
				if (password.equalsIgnoreCase(user.getAttribute("password"))) {
					validUser = true;
				}
			}
		}
		return validUser;
	}

	/**
	 * Write the Document memory object back to file
	 */
	private synchronized void writeToStore() throws AGSSecurityException {

		try {

			Transformer xformer = TransformerFactory.newInstance().newTransformer();
			xformer.setOutputProperty(OutputKeys.INDENT, "yes");
			FileOutputStream outFileStream = new FileOutputStream(pathToStore);
			Result result = new StreamResult(outFileStream);
			xformer.transform((Source) new DOMSource(xmlFileStore), result);

		} catch (Exception e) {
			throw new AGSSecurityException("Could not update the file store", e);
		}
	}

	private synchronized void readFromStore() throws AGSSecurityException {
		
		// Open the file
		try {
			File file = new File(pathToStore);
			
			DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			xmlFileStore = docBuilder.parse(file);
		} catch (Exception e) {
			xmlFileStore = null;
			throw new AGSSecurityException("Could not open the file store", e);
		}

		// Get the user, role, and user_roles nodes
		userList = xmlFileStore.getElementsByTagName(USERS).item(0).getChildNodes();
		roleList = xmlFileStore.getElementsByTagName(ROLES).item(0).getChildNodes();
		userRolesList = xmlFileStore.getElementsByTagName(USER_ROLES).item(0).getChildNodes();

		if ((userList == null) || (roleList == null) || (userRolesList == null)) {
			xmlFileStore = null;
			throw new AGSSecurityException("File store does not contain users, roles or user-roles information.");
		}
	} // readFromStore

}
