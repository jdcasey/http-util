/*******************************************************************************
 * Copyright 2011 John Casey
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.commonjava.util.http.ssl.threadlocal;

import static org.commonjava.util.http.ssl.SSLUtils.newKeyStore;
import static org.commonjava.util.http.ssl.SSLUtils.readCerts;
import static org.commonjava.util.http.ssl.SSLUtils.readKeyAndCert;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.commonjava.util.http.HTTPException;

@ApplicationScoped
public class ThreadLocalCredentialsProvider
    implements CredentialsProvider
{

    private final ThreadLocal<Map<AuthScope, Credentials>> credentials = new ThreadLocal<Map<AuthScope, Credentials>>();

    private final ThreadLocal<Map<AuthScope, String>> keyPasswords = new ThreadLocal<Map<AuthScope, String>>();

    private final ThreadLocal<KeyStore> keystores = new ThreadLocal<KeyStore>();

    private final ThreadLocal<KeyStore> truststores = new ThreadLocal<KeyStore>();

    public synchronized void bind( final Map<AuthScope, Credentials> creds )
    {
        this.credentials.set( creds );
    }

    public synchronized void bind( final AuthScope scope, final Credentials creds )
    {
        this.credentials.set( Collections.singletonMap( scope, creds ) );
    }

    public synchronized void bindKeyCerts( final Map<AuthScope, SSLKeyCert> keycerts )
        throws HTTPException
    {
        final Map<AuthScope, String> keyPasswords = new HashMap<AuthScope, String>();
        final KeyStore ks = newKeyStore();
        final KeyStore ts = newKeyStore();

        for ( final Map.Entry<AuthScope, SSLKeyCert> entry : keycerts.entrySet() )
        {
            final AuthScope scope = entry.getKey();
            final SSLKeyCert kc = entry.getValue();

            try
            {
                readKeyAndCert( scope, kc.getKeyPem(), kc.getKeyPassword(), ks );

                keyPasswords.put( scope, kc.getKeyPassword() );
            }
            catch ( final KeyStoreException e )
            {
                throw new HTTPException( "Failed to load client key / certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final NoSuchAlgorithmException e )
            {
                throw new HTTPException( "Failed to load client key / certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final CertificateException e )
            {
                throw new HTTPException( "Failed to load client key / certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final IOException e )
            {
                throw new HTTPException( "Failed to load client key / certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final InvalidKeySpecException e )
            {
                throw new HTTPException( "Failed to load client key / certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }

            try
            {
                readCerts( scope, kc.getCertPem(), ts );
            }
            catch ( final KeyStoreException e )
            {
                throw new HTTPException( "Failed to load server certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final NoSuchAlgorithmException e )
            {
                throw new HTTPException( "Failed to load server certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final CertificateException e )
            {
                throw new HTTPException( "Failed to load server certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }
            catch ( final IOException e )
            {
                throw new HTTPException( "Failed to load server certificates for: %s. Reason: %s", e, scope,
                                         e.getMessage() );
            }

        }

        this.keyPasswords.set( keyPasswords );
        this.keystores.set( ks );
        this.truststores.set( ts );
    }

    public synchronized void bindKeyCert( final AuthScope scope, final SSLKeyCert keycert )
        throws HTTPException
    {
        bindKeyCerts( Collections.singletonMap( scope, keycert ) );
    }

    @Override
    public void clear()
    {
        credentials.set( null );
    }

    @Override
    public synchronized void setCredentials( final AuthScope authscope, final Credentials creds )
    {
        bind( authscope, creds );
    }

    @Override
    public Credentials getCredentials( final AuthScope authscope )
    {
        final Map<AuthScope, Credentials> map = credentials.get();
        return map == null ? null : map.get( authscope );
    }

    public String getKeyPassword( final AuthScope scope )
    {
        final Map<AuthScope, String> map = keyPasswords.get();
        return map == null ? null : map.get( scope );
    }

    public KeyStore getKeyStore()
    {
        return keystores.get();
    }

    public KeyStore getTrustStore()
    {
        return truststores.get();
    }

}
