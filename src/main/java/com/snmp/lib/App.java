package com.snmp.lib;

import java.io.File;

import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.TransportMapping;
import org.snmp4j.agent.AgentConfigManager;
import org.snmp4j.agent.DefaultMOServer;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOServer;
import org.snmp4j.agent.cfg.EngineBootsCounterFile;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.UnsignedInteger32;
import org.snmp4j.transport.TransportMappings;
import org.snmp4j.util.ThreadPool;

public class App {
	public static void main(String[] args) throws DuplicateRegistrationException, InterruptedException {
		DefaultMOServer moServer = new DefaultMOServer();

		MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
		TransportMapping tm = TransportMappings.getInstance().createTransportMapping(new UdpAddress("0.0.0.0/18090"));
		if (tm != null) {
			messageDispatcher.addTransportMapping(tm);
		}
		MOScalar<Integer32> initValue = new MOScalar<>(new OID(new int[] { 1, 3, 6, 1, 4, 1, 21067, 14, 1, 1, 1 }),
				MOAccessImpl.ACCESS_READ_CREATE, new Integer32(0));
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC128SHA224());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC192SHA256());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC256SHA384());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC384SHA512());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivDES());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES128());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
		OctetString engineId = new OctetString(MPv3.createLocalEngineID());
		AgentConfigManager agent = new AgentConfigManager(engineId, messageDispatcher, null,
				new MOServer[] { moServer }, ThreadPool.create("Agent", 3), null, null,
				new EngineBootsCounterFile(new File("/tmp/bootcounter")));

		agent.initialize();

		// add proxy forwarder
		moServer.register(initValue, null);
		agent.setupProxyForwarder();
		agent.registerShutdownHook();

		agent.getVacmMIB().addViewTreeFamily(new OctetString("fullReadView"), new OID("1.3"), new OctetString(),
				VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
		agent.getVacmMIB().addViewTreeFamily(new OctetString("fullWriteView"), new OID("1.3"), new OctetString(),
				VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
		agent.getVacmMIB().addViewTreeFamily(new OctetString("fullNotifyView"), new OID("1.3"), new OctetString(),
				VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
		boolean isV2 = true;
		if (isV2) {
			agent.getSnmpCommunityMIB().addSnmpCommunityEntry(new OctetString("0"), new OctetString("jpublic"),
					new OctetString("cpublic"), engineId, new OctetString(), new OctetString(),
					StorageType.nonVolatile);

			agent.getVacmMIB().addGroup(SecurityModel.SECURITY_MODEL_SNMPv1, new OctetString("cpublic"),
					new OctetString("v1v2group"), StorageType.nonVolatile);
			agent.getVacmMIB().addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString("cpublic"),
					new OctetString("v1v2group"), StorageType.nonVolatile);

			agent.getVacmMIB().addAccess(new OctetString("v1v2group"), new OctetString(),
					SecurityModel.SECURITY_MODEL_ANY, SecurityLevel.NOAUTH_NOPRIV, MutableVACM.VACM_MATCH_EXACT,
					new OctetString("fullReadView"), new OctetString("fullWriteView"),
					new OctetString("fullNotifyView"), StorageType.nonVolatile);
		} else {
			
			boolean isAuth = true;
			boolean isPriv = true;
			int secLevel = SecurityLevel.NOAUTH_NOPRIV;
			if (isAuth && isPriv) {
				secLevel = SecurityLevel.AUTH_PRIV;
			} else if (isAuth) {
				secLevel = SecurityLevel.AUTH_NOPRIV;
			}
			String securityString = "SHADES";
			/*
			 * SHADES
			 * MD5DES
			 * SHA
			 * SHAAES128
			 * SHAAES192
			 * SHAAES256
			 * SHAAES256p
			 * MD5AES128
			 * MD5AES192
			 * MD5AES256
			 */
			
			 UsmUser user = new UsmUser(new OctetString(securityString),
                     AuthSHA.ID,
                     new OctetString("SHADESAuthPassword"),
                     PrivDES.ID,
                     new OctetString("SHADESPrivPassword"));
			 //usm.addUser(user.getSecurityName(), usm.getLocalEngineID(), user);
			 agent.getUsm().addUser(user.getSecurityName(), null, user);
			
			 
			 agent.getVacmMIB().addGroup(SecurityModel.SECURITY_MODEL_USM, new OctetString(securityString),
					new OctetString("v3group"), StorageType.nonVolatile);
			
			agent.getVacmMIB().addAccess(new OctetString("v3group"), new OctetString(),
					SecurityModel.SECURITY_MODEL_USM, secLevel, MutableVACM.VACM_MATCH_EXACT,
					new OctetString("fullReadView"), new OctetString("fullWriteView"),
					new OctetString("fullNotifyView"), StorageType.nonVolatile);

		}

		// now continue agent setup and launch it.
		agent.run();

		Thread.sleep(10 * 1000);
		initValue.setValue(new Integer32(2));
	}

}
