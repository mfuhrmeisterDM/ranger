package org.apache.ranger.authorization.hadoop;

import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.permission.FsAction;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.authorization.hadoop.constants.RangerHadoopConstants;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessResource;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;

public class RangerDatameerAuditHandler extends RangerDefaultAuditHandler {
	private static final Log LOG = LogFactory.getLog(RangerDatameerAuditHandler.class);

	private boolean         isAuditEnabled = false;
	private AuthzAuditEvent auditEvent     = null;
	private final String pathToBeValidated;
	private final boolean auditOnlyIfDenied;

	private static final String    HadoopModuleName = RangerConfiguration.getInstance().get(RangerHadoopConstants.AUDITLOG_HADOOP_MODULE_ACL_NAME_PROP , RangerHadoopConstants.DEFAULT_HADOOP_MODULE_ACL_NAME);
	private static final String    excludeUserList  = RangerConfiguration.getInstance().get(RangerHadoopConstants.AUDITLOG_HDFS_EXCLUDE_LIST_PROP, RangerHadoopConstants.AUDITLOG_EMPTY_STRING);
	private static HashSet<String> excludeUsers     = null;

	static {
		if (excludeUserList != null && excludeUserList.trim().length() > 0) {
			excludeUsers = new HashSet<String>();
			for(String excludeUser : excludeUserList.trim().split(",")) {
				excludeUser = excludeUser.trim();
				if (LOG.isDebugEnabled()) {
					LOG.debug("Adding exclude user [" + excludeUser + "]");
				}
				excludeUsers.add(excludeUser);
				}
		}
	}

	public RangerDatameerAuditHandler(String pathToBeValidated, boolean auditOnlyIfDenied) {
		this.pathToBeValidated = pathToBeValidated;
		this.auditOnlyIfDenied = auditOnlyIfDenied;
	}

	@Override
	public void processResult(RangerAccessResult result) {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerHdfsAuditHandler.logAudit(" + result + ")");
		}

		if(! isAuditEnabled && result.getIsAudited()) {
			isAuditEnabled = true;
		}

		if (auditEvent == null) {
			auditEvent = super.getAuthzEvents(result);
		}

		if (auditEvent != null) {
			RangerAccessRequest request = result.getAccessRequest();
			RangerAccessResource resource = request.getResource();
			String resourcePath = resource != null ? resource.getAsString() : null;

			// Overwrite fields in original auditEvent
			auditEvent.setEventTime(request.getAccessTime());
			auditEvent.setAccessType(request.getAction());
			auditEvent.setResourcePath(this.pathToBeValidated);
			auditEvent.setResultReason(resourcePath);

			auditEvent.setAccessResult((short) (result.getIsAllowed() ? 1 : 0));
			auditEvent.setPolicyId(result.getPolicyId());

			Set<String> tags = getTags(request);
			if (tags != null) {
				auditEvent.setTags(tags);
			}
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerHdfsAuditHandler.logAudit(" + result + "): " + auditEvent);
		}
	}
	
	public void logHadoopEvent(String path, FsAction action, boolean accessGranted) {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerHdfsAuditHandler.logHadoopEvent(" + path + ", " + action + ", " + accessGranted + ")");
		}

		if(auditEvent != null) {
			auditEvent.setResultReason(path);
			auditEvent.setAccessResult((short) (accessGranted ? 1 : 0));
			auditEvent.setAccessType(action == null ? null : action.toString());
			auditEvent.setAclEnforcer(HadoopModuleName);
			auditEvent.setPolicyId(-1);
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerHdfsAuditHandler.logHadoopEvent(" + path + ", " + action + ", " + accessGranted + "): " + auditEvent);
		}
	}

	public void flushAudit() {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerHdfsAuditHandler.flushAudit(" + isAuditEnabled + ", " + auditEvent + ")");
		}

		if(isAuditEnabled && auditEvent != null && !StringUtils.isEmpty(auditEvent.getAccessType())) {
			String username = auditEvent.getUser();

			boolean skipLog = (username != null && excludeUsers != null && excludeUsers.contains(username)) || (auditOnlyIfDenied && auditEvent.getAccessResult() != 0);

			if (! skipLog) {
				super.logAuthzAudit(auditEvent);
			}
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerHdfsAuditHandler.flushAudit(" + isAuditEnabled + ", " + auditEvent + ")");
		}
	}
}