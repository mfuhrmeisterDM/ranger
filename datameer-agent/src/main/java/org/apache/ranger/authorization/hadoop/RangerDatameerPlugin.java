package org.apache.ranger.authorization.hadoop;

import java.util.Random;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.authorization.hadoop.constants.RangerHadoopConstants;
import org.apache.ranger.plugin.resourcematcher.RangerPathResourceMatcher;
import org.apache.ranger.plugin.service.RangerBasePlugin;

public class RangerDatameerPlugin extends RangerBasePlugin {
	private static boolean hadoopAuthEnabled = RangerHadoopConstants.RANGER_ADD_HDFS_PERMISSION_DEFAULT;
	private static String fileNameExtensionSeparator;
	private static boolean optimizeSubAccessAuthEnabled = RangerHadoopConstants.RANGER_OPTIMIZE_SUBACCESS_AUTHORIZATION_DEFAULT;
	private static String randomizedWildcardPathName;

	public RangerDatameerPlugin() {
		super("hdfs", "hdfs");
	}
	
	public void init() {
		super.init();
		
		RangerDatameerPlugin.hadoopAuthEnabled = RangerConfiguration.getInstance().getBoolean(RangerHadoopConstants.RANGER_ADD_HDFS_PERMISSION_PROP, RangerHadoopConstants.RANGER_ADD_HDFS_PERMISSION_DEFAULT);
		RangerDatameerPlugin.fileNameExtensionSeparator = RangerConfiguration.getInstance().get(RangerDatameerAuthorizer.RANGER_FILENAME_EXTENSION_SEPARATOR_PROP, RangerDatameerAuthorizer.DEFAULT_FILENAME_EXTENSION_SEPARATOR);
		RangerDatameerPlugin.optimizeSubAccessAuthEnabled = RangerConfiguration.getInstance().getBoolean(RangerHadoopConstants.RANGER_OPTIMIZE_SUBACCESS_AUTHORIZATION_PROP, RangerHadoopConstants.RANGER_OPTIMIZE_SUBACCESS_AUTHORIZATION_DEFAULT);

		// Build random string of random length
		byte[] bytes = new byte[1];
		new Random().nextBytes(bytes);
		int count = bytes[0];
		count = count < 56 ? 56 : count;
		count = count > 112 ? 112 : count;

		String random = RandomStringUtils.random(count, "^&#@!%()-_+=@:;'<>`~abcdefghijklmnopqrstuvwxyz01234567890");
		randomizedWildcardPathName = RangerPathResourceMatcher.WILDCARD_ASTERISK + random + RangerPathResourceMatcher.WILDCARD_ASTERISK;
	}

	public static boolean isHadoopAuthEnabled() {
		return RangerDatameerPlugin.hadoopAuthEnabled;
	}
	public static String getFileNameExtensionSeparator() {
		return RangerDatameerPlugin.fileNameExtensionSeparator;
	}
	public static boolean isOptimizeSubAccessAuthEnabled() {
		return RangerDatameerPlugin.optimizeSubAccessAuthEnabled;
	}
	public static String getRandomizedWildcardPathName() {
		return RangerDatameerPlugin.randomizedWildcardPathName;
	}
}
