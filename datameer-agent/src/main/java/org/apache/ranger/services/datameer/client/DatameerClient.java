/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.services.datameer.client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.client.HadoopException;

public class DatameerClient extends BaseClient {

	private static final Log LOG = LogFactory.getLog(DatameerClient.class);

	private Configuration conf;

	public DatameerClient(String serviceName, Map<String, String> connectionProperties) {
		super(serviceName, connectionProperties, "datameer-client");
		conf = new Configuration();
		Set<String> rangerInternalPropertyKeys = getConfigHolder().getRangerInternalPropertyKeys();
		for (Map.Entry<String, String> entry : connectionProperties.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			if (!rangerInternalPropertyKeys.contains(key) && value != null) {
				conf.set(key, value);
			}
		}

	}

	public List<String> listFiles(final String baseDir, final String fileMatching, final List<String> pathList)
			throws Exception {

		List<String> fileList = new ArrayList<String>();
		String errMsg = " You can still save the repository and start creating "
				+ "policies, but you would not be able to use autocomplete for "
				+ "resource names. Check ranger_admin.log for more info.";
		try {
			String dirPrefix = (baseDir.endsWith("/") ? baseDir : (baseDir + "/"));
			String filterRegEx = null;
			if (fileMatching != null && fileMatching.trim().length() > 0) {
				filterRegEx = fileMatching.trim();
			}

			DatameerFileSystem fs = null;
			try {
				fs = DatameerFileSystem.get(conf);

				Path basePath = new Path(baseDir);
				FileStatus[] fileStatus = fs.listStatus(basePath);

				if (LOG.isDebugEnabled()) {
					LOG.debug("<== DatameerClient fileStatus : " + fileStatus.length + " PathList :" + pathList);
				}

				if (fileStatus != null) {
					if (fs.exists(basePath) && ArrayUtils.isEmpty(fileStatus)) {
						fileList.add(basePath.toString());
					} else {
						for (FileStatus stat : fileStatus) {
							Path path = stat.getPath();
							String pathComponent = path.getName();
							String prefixedPath = dirPrefix + pathComponent;
							if (pathList != null && pathList.contains(prefixedPath)) {
								continue;
							}
							if (filterRegEx == null) {
								fileList.add(prefixedPath);
							} else if (FilenameUtils.wildcardMatch(pathComponent, fileMatching)) {
								fileList.add(prefixedPath);
							}
						}
					}
				}
			} catch (UnknownHostException uhe) {
				String msgDesc = "listFilesInternal: Unable to connect using given config parameters"
						+ " of Hadoop environment [" + getSerivceName() + "].";
				HadoopException hdpException = new HadoopException(msgDesc, uhe);
				hdpException.generateResponseDataMap(false, getMessage(uhe), msgDesc + errMsg, null, null);
				if (LOG.isDebugEnabled()) {
					LOG.debug("<== DatameerClient listFilesInternal Error : " + uhe);
				}
				throw hdpException;
			} catch (FileNotFoundException fne) {
				String msgDesc = "listFiles: Unable to locate files using given config parameters " + "of environment ["
						+ getSerivceName() + "].";
				HadoopException hdpException = new HadoopException(msgDesc, fne);
				hdpException.generateResponseDataMap(false, getMessage(fne), msgDesc + errMsg, null, null);

				if (LOG.isDebugEnabled()) {
					LOG.debug("<== DatameerClient listFilesInternal Error : " + fne);
				}

				throw hdpException;
			}
		} catch (IOException ioe) {
			String msgDesc = "listFiles: Unable to get listing of files for directory " + baseDir + fileMatching
					+ "] from environment [" + getSerivceName() + "].";
			HadoopException hdpException = new HadoopException(msgDesc, ioe);
			hdpException.generateResponseDataMap(false, getMessage(ioe), msgDesc + errMsg, null, null);
			if (LOG.isDebugEnabled()) {
				LOG.debug("<== DatameerClient listFilesInternal Error : " + ioe);
			}
			throw hdpException;

		} catch (IllegalArgumentException iae) {
			String msgDesc = "Unable to get listing of files for directory [" + baseDir + "] from environment ["
					+ getSerivceName() + "].";
			HadoopException hdpException = new HadoopException(msgDesc, iae);
			hdpException.generateResponseDataMap(false, getMessage(iae), msgDesc + errMsg, null, null);
			if (LOG.isDebugEnabled()) {
				LOG.debug("<== DatameerClient listFilesInternal Error : " + iae);
			}
			throw hdpException;
		}
		return fileList;
	}

	public static final void main(String[] args) {

		if (args.length < 2) {
			System.err.println("USAGE: java " + DatameerClient.class.getName()
					+ " repositoryName  basedirectory  [filenameToMatch]");
			System.exit(1);
		}

		String repositoryName = args[0];
		String baseDir = args[1];
		String fileNameToMatch = (args.length == 2 ? null : args[2]);

		DatameerClient fs = new DatameerClient(repositoryName, new HashMap<String, String>());
		List<String> fsList = null;
		try {
			fsList = fs.listFiles(baseDir, fileNameToMatch, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (fsList != null && fsList.size() > 0) {
			for (String s : fsList) {
				System.out.println(s);
			}
		} else {
			System.err.println("Unable to get file listing for [" + baseDir + (baseDir.endsWith("/") ? "" : "/")
					+ fileNameToMatch + "]  in repository [" + repositoryName + "]");
		}
	}

	public static Map<String, Object> connectionTest(String serviceName, Map<String, String> configs) throws Exception {

		LOG.info("===> DatameerClient.connectionTest()");
		Map<String, Object> responseData = new HashMap<String, Object>();
		boolean connectivityStatus = false;

		String validateConfigsMsg = null;
		try {
			validateConnectionConfigs(configs);
		} catch (IllegalArgumentException e) {
			validateConfigsMsg = e.getMessage();
		}

		if (validateConfigsMsg == null) {

			DatameerClient connectionObj = new DatameerClient(serviceName, configs);
			if (connectionObj != null) {
				List<String> testResult = null;
				try {
					testResult = connectionObj.listFiles("/", null, null);
				} catch (HadoopException e) {
					LOG.error("<== DatameerClient.connectionTest() error " + e.getMessage(), e);
					throw e;
				}

				if (testResult != null && testResult.size() != 0) {
					connectivityStatus = true;
				}
			}
		}
		String testconnMsg = null;
		if (connectivityStatus) {
			testconnMsg = "ConnectionTest Successful";
			generateResponseDataMap(connectivityStatus, testconnMsg, testconnMsg, null, null, responseData);
		} else {
			testconnMsg = "Unable to retrieve any files using given parameters, "
					+ "You can still save the repository and start creating policies, "
					+ "but you would not be able to use autocomplete for resource names. "
					+ "Check ranger_admin.log for more info. ";
			String additionalMsg = (validateConfigsMsg != null) ? validateConfigsMsg : testconnMsg;
			generateResponseDataMap(connectivityStatus, testconnMsg, additionalMsg, null, null, responseData);
		}
		LOG.info("<== DatameerClient.connectionTest(): Status " + testconnMsg);
		return responseData;
	}

	public static void validateConnectionConfigs(Map<String, String> configs) throws IllegalArgumentException {
		// datameer username
		String username = configs.get("datameer.username");
		if ((username == null || username.isEmpty())) {
			throw new IllegalArgumentException("Value for datameer.username not specified");
		}

		// datameer password
		String password = configs.get("datameer.password");
		if ((password == null || password.isEmpty())) {
			throw new IllegalArgumentException("Value for datameer.password not specified");
		}
		// datameer url
		String datameerUrl = configs.get("datameer.url");
		if ((datameerUrl == null || datameerUrl.isEmpty())) {
			throw new IllegalArgumentException("Value for datameer.url not specified");
		}
	}
}
