/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ibm.appscan.jenkins.plugin.scanners;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.hcl.appscan.sdk.app.CloudApplicationProvider;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.app.ASEApplicationProvider;
import com.hcl.appscan.sdk.auth.IASEAuthenticationProvider;
import com.hcl.appscan.sdk.configuration.ConfigurationProviderFactory;
import com.hcl.appscan.sdk.configuration.IComponent;
import com.hcl.appscan.sdk.presence.CloudPresenceProvider;
import com.ibm.appscan.jenkins.plugin.Messages;
import com.ibm.appscan.jenkins.plugin.auth.ASECredentials;
import com.ibm.appscan.jenkins.plugin.auth.ASEJenkinsAuthenticationProvider;
import com.ibm.appscan.jenkins.plugin.auth.ASoCCredentials;
import com.ibm.appscan.jenkins.plugin.auth.JenkinsAuthenticationProvider;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.CUSTOM;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.EMPTY;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.EXTRA_FIELD;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.LOGIN_PASSWORD;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.LOGIN_USER;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.NORMAL;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.OPTIMIZATION;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.OPTIMIZED;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.PRESENCE_ID;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.PRODUCTION;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.SCAN_FILE;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.SCAN_TYPE;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.STAGING;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.TARGET;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.TEMPLATE_EXTENSION;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.TEMPLATE_EXTENSION2;
import static com.ibm.appscan.jenkins.plugin.scanners.ScannerConstants.TEST_POLICY;
import hudson.Extension;
import hudson.RelativePath;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.util.VariableResolver;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 *
 * @author anurag-s
 */
public class AppScanEnterpriseDynamicAnalyzer extends Scanner{

	private static final String ASE_DYNAMIC_ANALYZER = "AppScan Enterprise Dynamic Analyzer"; //$NON-NLS-1$
	private String m_loginUser;
        private String m_loginPassword;
        private String m_scanFile;
        private String m_optimization;
        private String m_extraField;
        private String m_applications;
	private String m_folderId;
        private String m_aseTestPolicies;
        private String m_aseTemplate;
        private String m_aseAgent;
	private String m_scanType;
	
	@Deprecated
	public AppScanEnterpriseDynamicAnalyzer(String target) {
		this(target, false, EMPTY,EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,EMPTY); 
	}
	
	@Deprecated
	public AppScanEnterpriseDynamicAnalyzer(String target, boolean hasOptions, String loginUser, String loginPassword, String folderId,String aseTestPolicies,String aseTemplate, String scanFile, 
			 String scanType,String optimization, String extraField, String aseAgent) {
		super(target, hasOptions);
		m_loginUser = loginUser;
		//m_loginPassword = Secret.fromString(loginPassword);
		m_folderId = folderId;
                m_aseTestPolicies=aseTestPolicies;
                m_aseTemplate=aseTemplate;
                m_aseAgent=aseAgent;
		m_scanFile = scanFile;
		m_scanType = scanFile != null && !scanFile.equals(EMPTY) ? CUSTOM : scanType;
		m_optimization = optimization;
		m_extraField = extraField;
	}
	
	@DataBoundConstructor
	public AppScanEnterpriseDynamicAnalyzer(String target, boolean hasOptions) {
		super(target, hasOptions);
		m_loginUser = EMPTY;
		//m_loginPassword = Secret.fromString(EMPTY);
		m_folderId = EMPTY;
                m_aseTestPolicies=EMPTY;
                m_aseTemplate=EMPTY;
                m_aseAgent=EMPTY;
		m_scanFile = EMPTY;
		m_scanType = EMPTY;
		m_optimization = EMPTY;
		m_extraField = EMPTY;
	}
	
	@DataBoundSetter
	public void setLoginUser(String loginUser) {
		m_loginUser = loginUser;
	}
	
	public String getLoginUser() {
		return m_loginUser;
	}
	
	@DataBoundSetter
	public void setLoginPassword(String loginPassword) {
		//m_loginPassword = Secret.fromString(loginPassword);
	}
	
	public Secret getLoginPassword() {
		return null;
	}

	@DataBoundSetter
	public void setFolderId(String folderId) {
		m_folderId = folderId;
	}
	
	public String getfolderId() {
		return m_folderId;
	}
	
	@DataBoundSetter
	public void setScanFile(String scanFile) {
		m_scanFile = scanFile;
	}
	
	public String getScanFile() {
		return m_scanFile;
	}
	
	@DataBoundSetter
	public void setAseTestPolicy(String aseTestPolicies) {
		m_aseTestPolicies = aseTestPolicies;
	}
	
	public String getAseTestPolicy() {
		return m_aseTestPolicies;
	}
        
        @DataBoundSetter
	public void setAseTemplate(String aseTemplate) {
		m_aseTemplate = aseTemplate;
	}
	
	public String getAseTemplate() {
		return m_aseTemplate;
	}
        
        @DataBoundSetter
	public void setAseAgent(String aseAgent) {
		m_aseAgent = aseAgent;
	}
	
	public String getAseAgent() {
		return m_aseAgent;
	}
        
	
	@DataBoundSetter
	public void setScanType(String scanType) {
		m_scanType = m_scanFile != null && !m_scanFile.equals(EMPTY) ? CUSTOM : scanType;
	}
	
	public String getScanType() {
		return m_scanType;
	}

	@DataBoundSetter
	public void setOptimization(String optimization) {
		m_optimization = optimization;
	}
	
	public String getOptimization() {
		return m_optimization;
	}
	
	@DataBoundSetter
	public void setExtraField(String extraField) {
		m_extraField = extraField;
	}
	
	public String getExtraField() {
		return m_extraField;
	}
	
	@Override
	public String getType() {
		return ASE_DYNAMIC_ANALYZER;
	}
	
	@Override
	public Map<String, String> getProperties(VariableResolver<String> resolver) {
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(TARGET, getTarget());
		//properties.put(LOGIN_USER, m_loginUser);
		//properties.put(LOGIN_PASSWORD, Secret.toString(m_loginPassword));
		properties.put(FOLDER_ID, m_folderId);
		//properties.put(SCAN_FILE, resolver == null ? m_scanFile : resolvePath(m_scanFile, resolver));
		properties.put(SCAN_TYPE, m_scanType);
		//properties.put(OPTIMIZATION, m_optimization.equals("Normal")? "false":"true");
		//properties.put(EXTRA_FIELD, m_extraField);
                properties.put("testPolicyId", m_aseTestPolicies);
                properties.put("applicationId", m_aseTestPolicies);
                properties.put("templateID", m_aseTemplate);
                
                
		return properties;
	}
	
	@Symbol("appscan_enterprise_dynamic_analyzer") //$NON-NLS-1$
	@Extension
	public static final class DescriptorImpl extends ScanDescriptor {
		
		@Override
		public String getDisplayName() {
			return ASE_DYNAMIC_ANALYZER;
		}
		
		public ListBoxModel doFillCredentialsItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) {
    		//We could just use listCredentials() to get the ListBoxModel, but need to work around JENKINS-12802.
    		ListBoxModel model = new ListBoxModel();
    		List<ASECredentials> credentialsList = CredentialsProvider.lookupCredentials(ASECredentials.class, context,
    				ACL.SYSTEM, Collections.<DomainRequirement>emptyList());
    		boolean hasSelected = false;
    		
    		for(ASECredentials creds : credentialsList) {
    			if(creds.getId().equals(credentials))
    				hasSelected = true;
    			String displayName = creds.getDescription();
    			displayName = displayName == null || displayName.equals("") ? creds.getUsername() + "/******" : displayName; //$NON-NLS-1$
    			model.add(new ListBoxModel.Option(displayName, creds.getId(), creds.getId().equals(credentials))); //$NON-NLS-1$
    		}
    		if(!hasSelected)
    			model.add(new ListBoxModel.Option("", "", true)); //$NON-NLS-1$ //$NON-NLS-2$
    		return model;
                }
    	
    	public ListBoxModel doFillApplicationItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) {
    		IASEAuthenticationProvider authProvider = new ASEJenkinsAuthenticationProvider(credentials, context);
    		Map<String, String> applications = new ASEApplicationProvider(authProvider).getApplications();
    		ListBoxModel model = new ListBoxModel();
    		
    		if(applications != null) {
        		List<Entry<String , String>> list=sortApplications(applications.entrySet());
    			
	    		for(Map.Entry<String, String> entry : list)
	    			model.add(entry.getValue(), entry.getKey());
    		}
    		return model;
    	}
    	
    	private List<Entry<String , String>> sortApplications(Set<Entry<String , String>> set) {
    		List<Entry<String , String>> list= new ArrayList<>(set);
    		if (list.size()>1) {
    			Collections.sort( list, new Comparator<Map.Entry<String, String>>()
                {
                    public int compare( Map.Entry<String, String> o1, Map.Entry<String, String> o2 )
                    {
                        return (o1.getValue().toLowerCase()).compareTo( o2.getValue().toLowerCase() );
                    }
                } );
    		}
		return list;
    	}
		
    	public ListBoxModel doFillFolderIdItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) { //$NON-NLS-1$
    		IASEAuthenticationProvider authProvider = new ASEJenkinsAuthenticationProvider(credentials, context);
    		      IComponent componentProvider = ConfigurationProviderFactory.getScanner("Folder", authProvider);
                      Map<String , String> items= componentProvider.getComponents();
    		ListBoxModel model = new ListBoxModel();
    		model.add(""); //$NON-NLS-1$
    		
    		if(items != null) {
	    		for(Map.Entry<String, String> entry : items.entrySet())
	    			model.add(entry.getValue(), entry.getKey());
    		}
    		return model;
    	}
        
        public ListBoxModel doFillAseTestPoliciesItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) { //$NON-NLS-1$
    		IASEAuthenticationProvider authProvider = new ASEJenkinsAuthenticationProvider(credentials, context);
    		      IComponent componentProvider = ConfigurationProviderFactory.getScanner("TestPolicies", authProvider);
                      Map<String , String> items= componentProvider.getComponents();
    		ListBoxModel model = new ListBoxModel();
    		model.add(""); //$NON-NLS-1$
    		
    		if(items != null) {
	    		for(Map.Entry<String, String> entry : items.entrySet())
	    			model.add(entry.getValue(), entry.getKey());
    		}
    		return model;
    	}
        
        public ListBoxModel doFillAseTemplateItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) { //$NON-NLS-1$
    		IASEAuthenticationProvider authProvider = new ASEJenkinsAuthenticationProvider(credentials, context);
    		      IComponent componentProvider = ConfigurationProviderFactory.getScanner("Template", authProvider);
                      Map<String , String> items= componentProvider.getComponents();
    		ListBoxModel model = new ListBoxModel();
    		model.add(""); //$NON-NLS-1$
    		
    		if(items != null) {
	    		for(Map.Entry<String, String> entry : items.entrySet())
	    			model.add(entry.getValue(), entry.getKey());
    		}
    		return model;
    	}
        
        public ListBoxModel doFillAseAgentItems(@QueryParameter String credentials, @AncestorInPath ItemGroup<?> context) { //$NON-NLS-1$
    		IASEAuthenticationProvider authProvider = new ASEJenkinsAuthenticationProvider(credentials, context);
    		      IComponent componentProvider = ConfigurationProviderFactory.getScanner("Agent", authProvider);
                      Map<String , String> items= componentProvider.getComponents();
    		ListBoxModel model = new ListBoxModel();
    		model.add(""); //$NON-NLS-1$
    		
    		if(items != null) {
	    		for(Map.Entry<String, String> entry : items.entrySet())
	    			model.add(entry.getValue(), entry.getKey());
    		}
    		return model;
    	}
		
    	public FormValidation doCheckScanFile(@QueryParameter String scanFile) {
    		if(!scanFile.trim().equals(EMPTY) && !scanFile.endsWith(TEMPLATE_EXTENSION) && !scanFile.endsWith(TEMPLATE_EXTENSION2))
    			return FormValidation.error(Messages.error_invalid_template_file());
    		return FormValidation.ok();
    	}
    	
    	public FormValidation doCheckTarget(@QueryParameter String target) {
    		return FormValidation.validateRequired(target);
    	}
	}
}
