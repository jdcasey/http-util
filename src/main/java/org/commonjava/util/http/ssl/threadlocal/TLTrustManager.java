package org.commonjava.util.http.ssl.threadlocal;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

import org.commonjava.util.logging.Logger;

public class TLTrustManager
    implements X509TrustManager
{

    private final Logger logger = new Logger( getClass() );

    private final ThreadLocalCredentialsProvider credProvider;

    private final X509TrustManager defaultManager;

    public TLTrustManager( final ThreadLocalCredentialsProvider credProvider, final X509TrustManager defaultManager )
    {
        this.credProvider = credProvider;
        this.defaultManager = defaultManager;
    }

    @Override
    public void checkClientTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        final KeyStore ks = credProvider.getKeyStore();
        int idx = 0;
        boolean found = true;
        for ( final X509Certificate cert : chain )
        {
            final String alias = cert.getSubjectX500Principal()
                                     .getName();
            try
            {
                if ( !ks.containsAlias( alias ) )
                {
                    found = false;
                    logger.error( "Certificate not found: " + alias + " (at index: " + idx + " in chain)" );

                    break;
                }
            }
            catch ( final KeyStoreException e )
            {
                logger.error( "Failed to lookup certificate with alias: " + alias + " (at index: " + idx
                    + " in chain.)", e );
                found = false;
                break;
            }

            idx++;
        }

        if ( !found )
        {
            defaultManager.checkServerTrusted( chain, authType );
        }
    }

    @Override
    public void checkServerTrusted( final X509Certificate[] chain, final String authType )
        throws CertificateException
    {
        final KeyStore ts = credProvider.getTrustStore();
        int idx = 0;
        boolean found = true;
        for ( final X509Certificate cert : chain )
        {
            final String alias = cert.getSubjectX500Principal()
                                     .getName();
            try
            {
                if ( !ts.containsAlias( alias ) )
                {
                    logger.error( "Certificate not found: " + alias + " (at index: " + idx
                        + " in chain). Checking default trust manager." );

                    found = false;
                    break;
                }
            }
            catch ( final KeyStoreException e )
            {
                logger.error( "Failed to lookup certificate with alias: " + alias + " (at index: " + idx
                    + " in chain). Checking default trust manager.", e );
                found = false;
                break;
            }

            idx++;
        }

        if ( !found )
        {
            defaultManager.checkServerTrusted( chain, authType );
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        final Set<X509Certificate> allCerts = new HashSet<X509Certificate>();
        KeyStore ks = credProvider.getKeyStore();

        Enumeration<String> en;
        try
        {
            en = ks.aliases();
            while ( en.hasMoreElements() )
            {
                final String alias = en.nextElement();
                allCerts.add( (X509Certificate) ks.getCertificate( alias ) );
            }
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to load aliases from keystore: %s", e, e.getMessage() );
        }

        ks = credProvider.getTrustStore();
        try
        {
            en = ks.aliases();
            while ( en.hasMoreElements() )
            {
                final String alias = en.nextElement();
                allCerts.add( (X509Certificate) ks.getCertificate( alias ) );
            }
        }
        catch ( final KeyStoreException e )
        {
            logger.error( "Failed to load aliases from truststore: %s", e, e.getMessage() );
        }

        allCerts.addAll( Arrays.asList( defaultManager.getAcceptedIssuers() ) );

        return allCerts.toArray( new X509Certificate[] {} );
    }

}
