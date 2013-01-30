package org.commonjava.util.http.util;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.io.IOUtils.closeQuietly;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.commonjava.util.http.HTTPException;

public final class SSLUtils
{

    private SSLUtils()
    {
    }

    public static KeyStore loadDefaultKeystore()
        throws HTTPException
    {
        KeyStore ks;
        try
        {
            ks = KeyStore.getInstance( KeyStore.getDefaultType() );
            ks.load( null );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Failed to load default KeyStore instance: %s", e, e.getMessage() );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to load default KeyStore instance: %s", e, e.getMessage() );
        }
        catch ( final CertificateException e )
        {
            throw new HTTPException( "Failed to load default KeyStore instance: %s", e, e.getMessage() );
        }
        catch ( final IOException e )
        {
            throw new HTTPException( "Failed to load default KeyStore instance: %s", e, e.getMessage() );
        }

        return ks;
    }

    public static void readKeyAndCert( final InputStream is, final String keyPass, final KeyStore ks )
        throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        final CertificateFactory certFactory = CertificateFactory.getInstance( "X.509" );
        final KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );

        final List<String> lines = readLines( is );
        String currentHeader = null;
        final StringBuilder current = new StringBuilder();
        final Map<String, String> entries = new LinkedHashMap<String, String>();
        for ( final String line : lines )
        {
            if ( line == null )
            {
                continue;
            }

            if ( line.startsWith( "-----BEGIN" ) )
            {
                currentHeader = line.trim();
                current.setLength( 0 );
            }
            else if ( line.startsWith( "-----END" ) )
            {
                entries.put( currentHeader, current.toString() );
            }
            else
            {
                current.append( line.trim() );
            }
        }

        final List<Certificate> certs = new ArrayList<Certificate>();
        for ( int pass = 0; pass < 2; pass++ )
        {
            for ( final Map.Entry<String, String> entry : entries.entrySet() )
            {
                final String header = entry.getKey();
                final byte[] data = decodeBase64( entry.getValue() );

                if ( pass > 0 && header.contains( "BEGIN PRIVATE KEY" ) )
                {
                    final KeySpec spec = new PKCS8EncodedKeySpec( data );
                    final PrivateKey key = keyFactory.generatePrivate( spec );
                    ks.setKeyEntry( "key", key, keyPass.toCharArray(), certs.toArray( new Certificate[] {} ) );
                }
                else if ( pass < 1 && header.contains( "BEGIN CERTIFICATE" ) )
                {
                    final Certificate c = certFactory.generateCertificate( new ByteArrayInputStream( data ) );

                    ks.setCertificateEntry( "certificate", c );
                    certs.add( c );
                }
            }
        }
    }

    public static void readCerts( final InputStream is, final String aliasPrefix, final KeyStore ks )
        throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException
    {
        final CertificateFactory certFactory = CertificateFactory.getInstance( "X.509" );

        final List<String> lines = readLines( is );
        final StringBuilder current = new StringBuilder();
        final List<String> entries = new ArrayList<String>();
        for ( final String line : lines )
        {
            if ( line == null )
            {
                continue;
            }

            if ( line.startsWith( "-----BEGIN" ) )
            {
                current.setLength( 0 );
            }
            else if ( line.startsWith( "-----END" ) )
            {
                entries.add( current.toString() );
            }
            else
            {
                current.append( line.trim() );
            }
        }

        int i = 0;
        for ( final String entry : entries )
        {
            final byte[] data = decodeBase64( entry );

            final Certificate c = certFactory.generateCertificate( new ByteArrayInputStream( data ) );

            ks.setCertificateEntry( aliasPrefix + i, c );
            i++;
        }
    }

    private static List<String> readLines( final InputStream is )
        throws IOException
    {
        final List<String> lines = new ArrayList<String>();
        BufferedReader reader = null;
        try
        {
            reader = new BufferedReader( new InputStreamReader( is ) );
            String line = null;
            while ( ( line = reader.readLine() ) != null )
            {
                lines.add( line.trim() );
            }
        }
        finally
        {
            closeQuietly( reader );
        }

        return lines;
    }
}
