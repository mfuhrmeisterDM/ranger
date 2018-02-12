package org.apache.ranger.authorization.hadoop;

import java.net.InetAddress;
import java.util.Date;
import java.util.Set;

import org.apache.hadoop.fs.permission.FsAction;
import org.apache.hadoop.hdfs.server.namenode.INode;
import org.apache.hadoop.ipc.Server;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.util.RangerAccessRequestUtil;

public class RangerDatameerAccessRequest extends RangerAccessRequestImpl {

	public RangerDatameerAccessRequest(INode inode, String path, String pathOwner, FsAction access, String accessType, String user, Set<String> groups, String clusterName) {
		super.setResource(new RangerDatameerResource(path, pathOwner));
		super.setAccessType(accessType);
		super.setUser(user);
		super.setUserGroups(groups);
		super.setAccessTime(new Date());
		super.setClientIPAddress(getRemoteIp());
		super.setAction(access.toString());
		super.setClusterName(clusterName);

		if (inode != null) {
			buildRequestContext(inode);
		}
	}
	
	private static String getRemoteIp() {
		String ret = null;
		InetAddress ip = Server.getRemoteIp();
		if (ip != null) {
			ret = ip.getHostAddress();
		}
		return ret;
	}
	private void buildRequestContext(final INode inode) {
		if (inode.isFile()) {
			String fileName = inode.getLocalName();
			RangerAccessRequestUtil.setTokenInContext(getContext(), RangerDatameerAuthorizer.KEY_FILENAME, fileName);
			int lastExtensionSeparatorIndex = fileName.lastIndexOf(RangerDatameerPlugin.getFileNameExtensionSeparator());
			if (lastExtensionSeparatorIndex != -1) {
				String baseFileName = fileName.substring(0, lastExtensionSeparatorIndex);
				RangerAccessRequestUtil.setTokenInContext(getContext(), RangerDatameerAuthorizer.KEY_BASE_FILENAME, baseFileName);
			}
		}
	}
}