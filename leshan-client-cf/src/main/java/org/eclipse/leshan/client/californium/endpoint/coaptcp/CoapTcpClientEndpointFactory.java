/*******************************************************************************
 * Copyright (c) 2022 Sierra Wireless and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.client.californium.endpoint.coaptcp;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.util.List;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.TcpEndpointContextMatcher;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.tcp.netty.TcpClientConnector;
import org.eclipse.leshan.client.californium.CaliforniumConnectionController;
import org.eclipse.leshan.client.californium.endpoint.CaliforniumClientEndpointFactory;
import org.eclipse.leshan.client.endpoint.ClientEndpointToolbox;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.client.servers.ServerInfo;
import org.eclipse.leshan.core.californium.DefaultExceptionTranslator;
import org.eclipse.leshan.core.californium.ExceptionTranslator;
import org.eclipse.leshan.core.californium.identity.DefaultCoapIdentityHandler;
import org.eclipse.leshan.core.californium.identity.IdentityHandler;
import org.eclipse.leshan.core.endpoint.Protocol;

public class CoapTcpClientEndpointFactory implements CaliforniumClientEndpointFactory {

    private final String loggingTag = null;
    protected EndpointContextMatcher unsecuredContextMatcher = new TcpEndpointContextMatcher();

    public CoapTcpClientEndpointFactory() {
    }

    @Override
    public Protocol getProtocol() {
        return Protocol.COAP_TCP;
    }

    @Override
    public Endpoint createCoapEndpoint(InetAddress clientAddress, Configuration defaultConfiguration,
            ServerInfo serverInfo, boolean clientInitiatedOnly, List<Certificate> trustStore,
            ClientEndpointToolbox toolbox) {
        return createEndpointBuilder(new InetSocketAddress(clientAddress, 0), serverInfo, defaultConfiguration).build();
    }

    /**
     * This method is intended to be overridden.
     *
     * @param address the IP address and port, if null the connector is bound to an ephemeral port on the wildcard
     *        address.
     * @param coapConfig the CoAP config used to create this endpoint.
     * @return the {@link Builder} used for unsecured communication.
     */
    protected CoapEndpoint.Builder createEndpointBuilder(InetSocketAddress address, ServerInfo serverInfo,
            Configuration coapConfig) {
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setConnector(createUnsecuredConnector(address, coapConfig));
        builder.setConfiguration(coapConfig);
        if (loggingTag != null) {
            builder.setLoggingTag("[" + loggingTag + "-coap://]");
        } else {
            builder.setLoggingTag("[coap://]");
        }
        if (unsecuredContextMatcher != null) {
            builder.setEndpointContextMatcher(unsecuredContextMatcher);
        }
        return builder;
    }

    /**
     * By default create an {@link UDPConnector}.
     * <p>
     * This method is intended to be overridden.
     *
     * @param address the IP address and port, if null the connector is bound to an ephemeral port on the wildcard
     *        address
     * @param coapConfig the Configuration
     * @return the {@link Connector} used for unsecured {@link CoapEndpoint}
     */
    protected Connector createUnsecuredConnector(InetSocketAddress address, Configuration coapConfig) {
        return new TcpClientConnector(coapConfig);
    }

    @Override
    public IdentityHandler createIdentityHandler() {
        // TODO TCP : maybe we need a more specific one
        return new DefaultCoapIdentityHandler();
    }

    @Override
    public ExceptionTranslator createExceptionTranslator() {
        // TODO TCP : maybe we need a more specific one
        return new DefaultExceptionTranslator();
    }

    @Override
    public CaliforniumConnectionController createConnectionController() {
        return new CaliforniumConnectionController() {
            @Override
            public void forceReconnection(Endpoint endpoint, ServerIdentity identity, boolean resume) {
                // no connection in coap, so nothing to do;
            }
        };
    }
}
