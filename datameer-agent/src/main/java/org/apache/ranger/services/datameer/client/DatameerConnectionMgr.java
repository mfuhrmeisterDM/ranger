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

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.apache.ranger.plugin.util.TimedEventUtil;


public class DatameerConnectionMgr {

	protected ConcurrentMap<String, DatameerClient> 	connectionCache = null;
	protected ConcurrentMap<String, Boolean> 		repoConnectStatusMap = null;

	private static final Logger LOG = Logger.getLogger(DatameerConnectionMgr.class);
	
	public DatameerConnectionMgr(){
		connectionCache  = new ConcurrentHashMap<String, DatameerClient>();
		repoConnectStatusMap = new ConcurrentHashMap<String, Boolean>();
	}
	
	
	public DatameerClient getConnection(final String serviceName, final String serviceType, final Map<String,String> configs) throws Exception{
		DatameerClient client = null;
		if (serviceType != null) {
			// get it from the cache
				client = connectionCache.get(serviceName);
				if (client == null) {
					if(configs == null) {
						final Callable<DatameerClient> connectDatameer = new Callable<DatameerClient>() {
							@Override
							public DatameerClient call() throws Exception {
								return new DatameerClient(serviceName, configs);
							}
						};
						
						try {
							client = TimedEventUtil.timedTask(connectDatameer, 10, TimeUnit.SECONDS);
						} catch(Exception e){
							LOG.error("Error establishing connection for Datameer repository : "
									+ serviceName, e);
							throw e;
						}
						
					} else {
												
						final Callable<DatameerClient> connectDatameer = new Callable<DatameerClient>() {
							@Override
							public DatameerClient call() throws Exception {
								return new DatameerClient(serviceName, configs);
							}
						};
						
						try {
							client = TimedEventUtil.timedTask(connectDatameer, 5, TimeUnit.SECONDS);
						} catch(Exception e){
							LOG.error("Error establishing connection for Datameer repository : "
									+ serviceName + " using configuration : " + configs, e);
							throw e;
						}
					}	
					DatameerClient oldClient = connectionCache.putIfAbsent(serviceName, client);
					if (oldClient != null) {
						// in the meantime someone else has put a valid client into the cache, let's use that instead.
						client = oldClient;
					}
					repoConnectStatusMap.put(serviceName, true);
 				} else {
 					List<String> testConnect = null;
					try {
						testConnect = client.listFiles("/", "*",null);
					} catch ( Exception e) {
						LOG.error("Error establishing connection for Datameer repository : "
							+ serviceName + " using configuration : " + configs, e);
						throw e;
					}
					if(testConnect == null){
						connectionCache.put(serviceName, client);
						client = getConnection(serviceName,serviceType,configs);
					}
				}
		} else {
			LOG.error("Service not found with name " + serviceName, new Throwable());
		}

		return client;
	}
}
