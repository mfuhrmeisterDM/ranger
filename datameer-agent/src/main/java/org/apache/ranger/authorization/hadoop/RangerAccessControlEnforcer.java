package org.apache.ranger.authorization.hadoop;

import static org.apache.ranger.authorization.hadoop.constants.RangerHadoopConstants.EXECUTE_ACCCESS_TYPE;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.permission.FsAction;
import org.apache.hadoop.hdfs.server.namenode.INode;
import org.apache.hadoop.hdfs.server.namenode.INodeAttributeProvider;
import org.apache.hadoop.hdfs.server.namenode.INodeAttributes;
import org.apache.hadoop.hdfs.server.namenode.INodeDirectory;
import org.apache.hadoop.hdfs.server.namenode.INodeAttributeProvider.AccessControlEnforcer;
import org.apache.hadoop.hdfs.util.ReadOnlyList;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.authorization.hadoop.constants.RangerHadoopConstants;
import org.apache.ranger.authorization.hadoop.exceptions.RangerAccessControlException;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.util.RangerPerfTracer;

import com.google.common.collect.Sets;

public class RangerAccessControlEnforcer implements AccessControlEnforcer {
	private static final Log LOG = LogFactory.getLog(RangerDatameerAuthorizer.class);
	private static final Log PERF_HDFSAUTH_REQUEST_LOG = RangerPerfTracer.getPerfLogger("hdfsauth.request");
	private INodeAttributeProvider.AccessControlEnforcer defaultEnforcer = null;
	static final Map<FsAction, Set<String>> access2ActionListMapper = new HashMap<FsAction, Set<String>>();
	static RangerDatameerPlugin rangerPlugin;

	public RangerAccessControlEnforcer(AccessControlEnforcer defaultEnforcer) {
		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.RangerAccessControlEnforcer()");
		}

		this.defaultEnforcer = defaultEnforcer;

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerAccessControlEnforcer.RangerAccessControlEnforcer()");
		}
	}

	@Override
	public void checkPermission(String fsOwner, String superGroup, UserGroupInformation ugi,
								INodeAttributes[] inodeAttrs, INode[] inodes, byte[][] pathByNameArr,
								int snapshotId, String path, int ancestorIndex, boolean doCheckOwner,
								FsAction ancestorAccess, FsAction parentAccess, FsAction access,
								FsAction subAccess, boolean ignoreEmptyDir) throws AccessControlException {
		AuthzStatus            authzStatus = AuthzStatus.NOT_DETERMINED;
		RangerDatameerPlugin       plugin        = rangerPlugin;
		RangerDatameerAuditHandler auditHandler  = null;
		String                 user          = ugi != null ? ugi.getShortUserName() : null;
		Set<String>            groups        = ugi != null ? Sets.newHashSet(ugi.getGroupNames()) : null;

		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.checkPermission("
					+ "fsOwner=" + fsOwner + "; superGroup=" + superGroup + ", inodesCount=" + (inodes != null ? inodes.length : 0)
					+ ", snapshotId=" + snapshotId + ", user=" + user + ", path=" + path + ", ancestorIndex=" + ancestorIndex
					+ ", doCheckOwner="+ doCheckOwner + ", ancestorAccess=" + ancestorAccess + ", parentAccess=" + parentAccess
					+ ", access=" + access + ", subAccess=" + subAccess + ", ignoreEmptyDir=" + ignoreEmptyDir + ")");
		}

		RangerPerfTracer perf = null;

		if(RangerPerfTracer.isPerfTraceEnabled(PERF_HDFSAUTH_REQUEST_LOG)) {
			perf = RangerPerfTracer.getPerfTracer(PERF_HDFSAUTH_REQUEST_LOG, "RangerHdfsAuthorizer.checkPermission(path=" + path + ")");
		}

		try {
			final boolean isTraverseOnlyCheck = access == null && parentAccess == null && ancestorAccess == null && subAccess == null;
			INode   ancestor            = null;
			INode   parent              = null;
			INode   inode               = null;

			if(plugin != null && !ArrayUtils.isEmpty(inodes)) {
				if(ancestorIndex >= inodes.length) {
					ancestorIndex = inodes.length - 1;
				}

				for(; ancestorIndex >= 0 && inodes[ancestorIndex] == null; ancestorIndex--);

				authzStatus = AuthzStatus.ALLOW;

				ancestor = inodes.length > ancestorIndex && ancestorIndex >= 0 ? inodes[ancestorIndex] : null;
				parent   = inodes.length > 1 ? inodes[inodes.length - 2] : null;
				inode    = inodes[inodes.length - 1]; // could be null while creating a new file

				auditHandler = new RangerDatameerAuditHandler(path, isTraverseOnlyCheck);

				/* Hadoop versions prior to 2.8.0 didn't ask for authorization of parent/ancestor traversal for
				 * reading or writing a file. However, Hadoop version 2.8.0 and later ask traversal authorization for
				 * such accesses. This means 2 authorization calls are made to the authorizer for a single access:
				 *  1. traversal authorization (where access, parentAccess, ancestorAccess and subAccess are null)
				 *  2. authorization for the requested permission (such as READ for reading a file)
				 *
				 * For the first call, Ranger authorizer would:
				 * - Deny traversal if Ranger policies explicitly deny EXECUTE access on the parent or closest ancestor
				 * - Else, allow traversal
				 *
				 * There are no changes to authorization of the second call listed above.
				 *
				 * This approach would ensure that Ranger authorization will continue to work with existing policies,
				 * without requiring policy migration/update, for the changes in behaviour in Hadoop 2.8.0.
				 */
				if(isTraverseOnlyCheck) {
					authzStatus = traverseOnlyCheck(inode, inodeAttrs, parent, ancestor, ancestorIndex, user, groups, plugin, auditHandler);
				}

				// checkStickyBit
				if (authzStatus == AuthzStatus.ALLOW && parentAccess != null && parentAccess.implies(FsAction.WRITE) && parent != null && inode != null) {
					if (parent.getFsPermission() != null && parent.getFsPermission().getStickyBit()) {
					    // user should be owner of the parent or the inode
					    authzStatus = (StringUtils.equals(parent.getUserName(), user) || StringUtils.equals(inode.getUserName(), user)) ? AuthzStatus.ALLOW : AuthzStatus.NOT_DETERMINED;
					}
				}

				// checkAncestorAccess
				if(authzStatus == AuthzStatus.ALLOW && ancestorAccess != null && ancestor != null) {
					INodeAttributes ancestorAttribs = inodeAttrs.length > ancestorIndex ? inodeAttrs[ancestorIndex] : null;

					authzStatus = isAccessAllowed(ancestor, ancestorAttribs, ancestorAccess, user, groups, plugin, auditHandler);
					if (authzStatus == AuthzStatus.NOT_DETERMINED) {
						authzStatus = checkDefaultEnforcer(fsOwner, superGroup, ugi, inodeAttrs, inodes,
										pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
										ancestorAccess, null, null, null, ignoreEmptyDir,
										isTraverseOnlyCheck, ancestor, parent, inode, auditHandler);
					}
				}

				// checkParentAccess
				if(authzStatus == AuthzStatus.ALLOW && parentAccess != null && parent != null) {
					INodeAttributes parentAttribs = inodeAttrs.length > 1 ? inodeAttrs[inodeAttrs.length - 2] : null;

					authzStatus = isAccessAllowed(parent, parentAttribs, parentAccess, user, groups, plugin, auditHandler);
					if (authzStatus == AuthzStatus.NOT_DETERMINED) {
						authzStatus = checkDefaultEnforcer(fsOwner, superGroup, ugi, inodeAttrs, inodes,
										pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
										null, parentAccess, null, null, ignoreEmptyDir,
										isTraverseOnlyCheck, ancestor, parent, inode, auditHandler);
					}
				}

				// checkINodeAccess
				if(authzStatus == AuthzStatus.ALLOW && access != null && inode != null) {
					INodeAttributes inodeAttribs = inodeAttrs.length > 0 ? inodeAttrs[inodeAttrs.length - 1] : null;

					authzStatus = isAccessAllowed(inode, inodeAttribs, access, user, groups, plugin, auditHandler);
					if (authzStatus == AuthzStatus.NOT_DETERMINED) {
						authzStatus = checkDefaultEnforcer(fsOwner, superGroup, ugi, inodeAttrs, inodes,
										pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
										null, null, access, null, ignoreEmptyDir,
										isTraverseOnlyCheck, ancestor, parent, inode, auditHandler);
					}
				}

				// checkSubAccess
				if(authzStatus == AuthzStatus.ALLOW && subAccess != null && inode != null && inode.isDirectory()) {
					Stack<INodeDirectory> directories = new Stack<INodeDirectory>();

					for(directories.push(inode.asDirectory()); !directories.isEmpty(); ) {
						INodeDirectory      dir   = directories.pop();
						ReadOnlyList<INode> cList = dir.getChildrenList(snapshotId);

						if (!(cList.isEmpty() && ignoreEmptyDir)) {
							INodeAttributes dirAttribs = dir.getSnapshotINode(snapshotId);

							authzStatus = isAccessAllowed(dir, dirAttribs, subAccess, user, groups, plugin, auditHandler);

							if(authzStatus != AuthzStatus.ALLOW) {
								break;
							}

							AuthzStatus subDirAuthStatus = AuthzStatus.NOT_DETERMINED;

							boolean optimizeSubAccessAuthEnabled = RangerDatameerPlugin.isOptimizeSubAccessAuthEnabled();

							if (optimizeSubAccessAuthEnabled) {
								subDirAuthStatus = isAccessAllowedForHierarchy(dir, dirAttribs, subAccess, user, groups, plugin);
							}

							if (subDirAuthStatus != AuthzStatus.ALLOW) {
								for(INode child : cList) {
									if (child.isDirectory()) {
										directories.push(child.asDirectory());
									}
								}
							}
						}
					}
					if (authzStatus == AuthzStatus.NOT_DETERMINED) {

						authzStatus = checkDefaultEnforcer(fsOwner, superGroup, ugi, inodeAttrs, inodes,
										pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
										null, null, null, subAccess, ignoreEmptyDir,
										isTraverseOnlyCheck, ancestor, parent, inode, auditHandler);

					}
				}

				// checkOwnerAccess
				if(authzStatus == AuthzStatus.ALLOW && doCheckOwner) {
					INodeAttributes inodeAttribs = inodeAttrs.length > 0 ? inodeAttrs[inodeAttrs.length - 1] : null;
					String          owner        = inodeAttribs != null ? inodeAttribs.getUserName() : null;

					authzStatus = StringUtils.equals(user, owner) ? AuthzStatus.ALLOW : AuthzStatus.NOT_DETERMINED;
				}
			}

			if (authzStatus == AuthzStatus.NOT_DETERMINED) {
				authzStatus = checkDefaultEnforcer(fsOwner, superGroup, ugi, inodeAttrs, inodes,
								pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
								ancestorAccess, parentAccess, access, subAccess, ignoreEmptyDir,
								isTraverseOnlyCheck, ancestor, parent, inode, auditHandler);
			}

			if(authzStatus != AuthzStatus.ALLOW) {
				FsAction action = access;

				if(action == null) {
					if(parentAccess != null)  {
						action = parentAccess;
					} else if(ancestorAccess != null) {
						action = ancestorAccess;
					} else {
						action = FsAction.EXECUTE;
					}
				}

				throw new RangerAccessControlException("Permission denied: user=" + user + ", access=" + action + ", inode=\"" + path + "\"");
			}
		} finally {
			if(auditHandler != null) {
				auditHandler.flushAudit();
			}

			RangerPerfTracer.log(perf);

			if(LOG.isDebugEnabled()) {
				LOG.debug("<== RangerAccessControlEnforcer.checkPermission(" + path + ", " + access + ", user=" + user + ") : " + authzStatus);
			}
		}
	}

	/*
	    Check if parent or ancestor of the file being accessed is denied EXECUTE permission. If not, assume that Ranger-acls
	    allowed EXECUTE access. Do not audit this authorization check if resource is a file unless access is explicitly denied
	 */
	private AuthzStatus traverseOnlyCheck(INode inode, INodeAttributes[] inodeAttrs, INode parent, INode ancestor, int ancestorIndex,
										  String user, Set<String> groups, RangerDatameerPlugin plugin, RangerDatameerAuditHandler auditHandler) {

		String path = inode != null ? inode.getFullPathName() : null;

		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.traverseOnlyCheck("
					+ "path=" + path + ", user=" + user + ", groups=" + groups + ")");
		}
		final AuthzStatus ret;

		INode nodeToCheck = inode;
		INodeAttributes nodeAttribs = inodeAttrs.length > 0 ? inodeAttrs[inodeAttrs.length - 1] : null;
		boolean skipAuditOnAllow = false;

		if (nodeToCheck == null || nodeToCheck.isFile()) {
			skipAuditOnAllow = true;
			if (parent != null) {
				nodeToCheck = parent;
				nodeAttribs = inodeAttrs.length > 1 ? inodeAttrs[inodeAttrs.length - 2] : null;
			} else if (ancestor != null) {
				nodeToCheck = ancestor;
				nodeAttribs = inodeAttrs.length > ancestorIndex ? inodeAttrs[ancestorIndex] : null;
			}
		}

		if (nodeToCheck != null) {
			ret = isAccessAllowedForTraversal(nodeToCheck, nodeAttribs, user, groups, plugin, auditHandler, skipAuditOnAllow);
		} else {
			ret = AuthzStatus.ALLOW;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("<== RangerAccessControlEnforcer.traverseOnlyCheck("
					+ "path=" + path + ", user=" + user + ", groups=" + groups + ") : " + ret);
		}
		return ret;
	}

	private AuthzStatus isAccessAllowedForTraversal(INode inode, INodeAttributes inodeAttribs, String user, Set<String> groups, RangerDatameerPlugin plugin, RangerDatameerAuditHandler auditHandler, boolean skipAuditOnAllow) {
		final AuthzStatus ret;
		String path = inode.getFullPathName();
		String pathOwner = inodeAttribs != null ? inodeAttribs.getUserName() : null;
		String clusterName = plugin.getClusterName();
		FsAction access = FsAction.EXECUTE;


		if (pathOwner == null) {
			pathOwner = inode.getUserName();
		}

		if (RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH_ALT.equals(path)) {
			path = RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.isAccessAllowedForTraversal(" + path + ", " + access + ", " + user + ", " + skipAuditOnAllow + ")");
		}

		RangerDatameerAccessRequest request = new RangerDatameerAccessRequest(inode, path, pathOwner, access, EXECUTE_ACCCESS_TYPE, user, groups, clusterName);

		RangerAccessResult result = plugin.isAccessAllowed(request, null);

		if (result != null && result.getIsAccessDetermined() && !result.getIsAllowed()) {
			ret = AuthzStatus.DENY;
		} else {
			ret = AuthzStatus.ALLOW;
		}

		if (result != null && (!skipAuditOnAllow || ret == AuthzStatus.DENY)) {
			auditHandler.processResult(result);
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("<== RangerAccessControlEnforcer.isAccessAllowedForTraversal(" + path + ", " + access + ", " + user + ", " + skipAuditOnAllow + "): " + ret);
		}

		return ret;
	}

	private AuthzStatus checkDefaultEnforcer(String fsOwner, String superGroup, UserGroupInformation ugi,
								INodeAttributes[] inodeAttrs, INode[] inodes, byte[][] pathByNameArr,
								int snapshotId, String path, int ancestorIndex, boolean doCheckOwner,
								FsAction ancestorAccess, FsAction parentAccess, FsAction access,
								FsAction subAccess, boolean ignoreEmptyDir,
                                boolean isTraverseOnlyCheck, INode ancestor,
											 INode parent, INode inode, RangerDatameerAuditHandler auditHandler
											 ) throws AccessControlException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.checkDefaultEnforcer("
					+ "fsOwner=" + fsOwner + "; superGroup=" + superGroup + ", inodesCount=" + (inodes != null ? inodes.length : 0)
					+ ", snapshotId=" + snapshotId + ", path=" + path + ", ancestorIndex=" + ancestorIndex
					+ ", doCheckOwner=" + doCheckOwner + ", ancestorAccess=" + ancestorAccess + ", parentAccess=" + parentAccess
					+ ", access=" + access + ", subAccess=" + subAccess + ", ignoreEmptyDir=" + ignoreEmptyDir
					+ ", isTraverseOnlyCheck=" + isTraverseOnlyCheck + ",ancestor=" + (ancestor == null ? null : ancestor.getFullPathName())
					+ ", parent=" + (parent == null ? null : parent.getFullPathName()) + ", inode=" + (inode == null ? null : inode.getFullPathName())
					+ ")");
		}

		AuthzStatus authzStatus = AuthzStatus.NOT_DETERMINED;
		if(RangerDatameerPlugin.isHadoopAuthEnabled() && defaultEnforcer != null) {

			RangerPerfTracer hadoopAuthPerf = null;

			if(RangerPerfTracer.isPerfTraceEnabled(PERF_HDFSAUTH_REQUEST_LOG)) {
				hadoopAuthPerf = RangerPerfTracer.getPerfTracer(PERF_HDFSAUTH_REQUEST_LOG, "RangerAccessControlEnforcer.checkDefaultEnforcer(path=" + path + ")");
			}

			try {
				defaultEnforcer.checkPermission(fsOwner, superGroup, ugi, inodeAttrs, inodes,
						pathByNameArr, snapshotId, path, ancestorIndex, doCheckOwner,
						ancestorAccess, parentAccess, access, subAccess, ignoreEmptyDir);

				authzStatus = AuthzStatus.ALLOW;
			} finally {
				if (auditHandler != null) {
					INode nodeChecked = inode;
					FsAction action = access;
					if (isTraverseOnlyCheck) {
						if (nodeChecked == null || nodeChecked.isFile()) {
							if (parent != null) {
								nodeChecked = parent;
							} else if (ancestor != null) {
								nodeChecked = ancestor;
							}
						}

						action = FsAction.EXECUTE;
					} else if (action == null || action == FsAction.NONE) {
						if (parentAccess != null && parentAccess != FsAction.NONE) {
							nodeChecked = parent;
							action = parentAccess;
						} else if (ancestorAccess != null && ancestorAccess != FsAction.NONE) {
							nodeChecked = ancestor;
							action = ancestorAccess;
						} else if (subAccess != null && subAccess != FsAction.NONE) {
							action = subAccess;
						}
					}

					String pathChecked = nodeChecked != null ? nodeChecked.getFullPathName() : path;

					auditHandler.logHadoopEvent(pathChecked, action, authzStatus == AuthzStatus.ALLOW);
				}
				RangerPerfTracer.log(hadoopAuthPerf);
			}
		}
		LOG.debug("<== RangerAccessControlEnforcer.checkDefaultEnforcer("
				+ "fsOwner=" + fsOwner + "; superGroup=" + superGroup + ", inodesCount=" + (inodes != null ? inodes.length : 0)
				+ ", snapshotId=" + snapshotId + ", path=" + path + ", ancestorIndex=" + ancestorIndex
				+ ", doCheckOwner="+ doCheckOwner + ", ancestorAccess=" + ancestorAccess + ", parentAccess=" + parentAccess
				+ ", access=" + access + ", subAccess=" + subAccess + ", ignoreEmptyDir=" + ignoreEmptyDir
				+ ", isTraverseOnlyCheck=" + isTraverseOnlyCheck + ",ancestor=" + (ancestor == null ? null : ancestor.getFullPathName())
				+ ", parent=" + (parent == null ? null : parent.getFullPathName()) + ", inode=" + (inode == null ? null : inode.getFullPathName())
				+ ") : " + authzStatus );

		return authzStatus;
	}

	private AuthzStatus isAccessAllowed(INode inode, INodeAttributes inodeAttribs, FsAction access, String user, Set<String> groups, RangerDatameerPlugin plugin, RangerDatameerAuditHandler auditHandler) {
		AuthzStatus ret       = null;
		String      path      = inode != null ? inode.getFullPathName() : null;
		String      pathOwner = inodeAttribs != null ? inodeAttribs.getUserName() : null;
		String 		clusterName = plugin.getClusterName();

		if(pathOwner == null && inode != null) {
			pathOwner = inode.getUserName();
		}

		if (RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH_ALT.equals(path)) {
			path = RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH;
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.isAccessAllowed(" + path + ", " + access + ", " + user + ")");
		}

		Set<String> accessTypes = access2ActionListMapper.get(access);

		if(accessTypes == null) {
			LOG.warn("RangerAccessControlEnforcer.isAccessAllowed(" + path + ", " + access + ", " + user + "): no Ranger accessType found for " + access);

			accessTypes = access2ActionListMapper.get(FsAction.NONE);
		}

		for(String accessType : accessTypes) {
			RangerDatameerAccessRequest request = new RangerDatameerAccessRequest(inode, path, pathOwner, access, accessType, user, groups, clusterName);

			RangerAccessResult result = plugin.isAccessAllowed(request, auditHandler);

			if (result == null || !result.getIsAccessDetermined()) {
				ret = AuthzStatus.NOT_DETERMINED;
				// don't break yet; subsequent accessType could be denied
			} else if(! result.getIsAllowed()) { // explicit deny
				ret = AuthzStatus.DENY;
				break;
			} else { // allowed
				if(!AuthzStatus.NOT_DETERMINED.equals(ret)) { // set to ALLOW only if there was no NOT_DETERMINED earlier
					ret = AuthzStatus.ALLOW;
				}
			}
		}

		if(ret == null) {
			ret = AuthzStatus.NOT_DETERMINED;
		}

		if(LOG.isDebugEnabled()) {
			LOG.debug("<== RangerAccessControlEnforcer.isAccessAllowed(" + path + ", " + access + ", " + user + "): " + ret);
		}

		return ret;
	}

	private AuthzStatus isAccessAllowedForHierarchy(INode inode, INodeAttributes inodeAttribs, FsAction access, String user, Set<String> groups, RangerDatameerPlugin plugin) {
		AuthzStatus ret   = null;
		String  path      = inode != null ? inode.getFullPathName() : null;
		String  pathOwner = inodeAttribs != null ? inodeAttribs.getUserName() : null;
		String 		clusterName = plugin.getClusterName();

		if (pathOwner == null && inode != null) {
			pathOwner = inode.getUserName();
		}

		if (RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH_ALT.equals(path)) {
			path = RangerHadoopConstants.HDFS_ROOT_FOLDER_PATH;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("==> RangerAccessControlEnforcer.isAccessAllowedForHierarchy(" + path + ", " + access + ", " + user + ")");
		}

		if (path != null) {

			Set<String> accessTypes = access2ActionListMapper.get(access);

			if (accessTypes == null) {
				LOG.warn("RangerAccessControlEnforcer.isAccessAllowedForHierarchy(" + path + ", " + access + ", " + user + "): no Ranger accessType found for " + access);

				accessTypes = access2ActionListMapper.get(FsAction.NONE);
			}

			String subDirPath = path;
			if (subDirPath.charAt(subDirPath.length() - 1) != org.apache.hadoop.fs.Path.SEPARATOR_CHAR) {
				subDirPath = subDirPath + Character.toString(org.apache.hadoop.fs.Path.SEPARATOR_CHAR);
			}
			subDirPath = subDirPath + RangerDatameerPlugin.getRandomizedWildcardPathName();

			for (String accessType : accessTypes) {
				RangerDatameerAccessRequest request = new RangerDatameerAccessRequest(null, subDirPath, pathOwner, access, accessType, user, groups, clusterName);

				RangerAccessResult result = plugin.isAccessAllowed(request, null);

				if (result == null || !result.getIsAccessDetermined()) {
					ret = AuthzStatus.NOT_DETERMINED;
					// don't break yet; subsequent accessType could be denied
				} else if(! result.getIsAllowed()) { // explicit deny
					ret = AuthzStatus.DENY;
					break;
				} else { // allowed
					if(!AuthzStatus.NOT_DETERMINED.equals(ret)) { // set to ALLOW only if there was no NOT_DETERMINED earlier
						ret = AuthzStatus.ALLOW;
					}
				}
			}
		}

		if(ret == null) {
			ret = AuthzStatus.NOT_DETERMINED;
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("<== RangerAccessControlEnforcer.isAccessAllowedForHierarchy(" + path + ", " + access + ", " + user + "): " + ret);
		}

		return ret;
	}
}