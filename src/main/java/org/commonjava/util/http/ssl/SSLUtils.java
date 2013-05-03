package org.commonjava.util.http.ssl;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.io.IOUtils.closeQuietly;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.auth.AuthScope;
import org.commonjava.util.http.HTTPException;

public final class SSLUtils
{

    private static final String CLIENT_PREFIX = "client::";

    private static final String SERVER_PREFIX = "server::";

    private static final String AUTH_SCOPE_ALIAS_PATTERN = ".+::(.+):(\\d+)";

    private SSLUtils()
    {
    }

    public static X509KeyManager getDefaultKeyManager()
        throws HTTPException
    {
        final KeyStore ks = loadDefaultKeystore();

        KeyManagerFactory kmf;
        try
        {
            kmf = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm() );
            kmf.init( ks, null );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }
        catch ( final UnrecoverableKeyException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Cannot initialize KeyManagerFactory: %s", e, e.getMessage() );
        }

        X509KeyManager km = null;
        for ( final KeyManager keyManager : kmf.getKeyManagers() )
        {
            if ( keyManager instanceof X509KeyManager )
            {
                km = (X509KeyManager) keyManager;
            }
        }

        return km;
    }

    public static X509TrustManager getDefaultTrustManager()
        throws HTTPException
    {
        TrustManagerFactory dtmf;
        try
        {
            dtmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
            dtmf.init( (KeyStore) null );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new HTTPException( "Failed to initialize default trust-store: %s", e, e.getMessage() );
        }
        catch ( final KeyStoreException e )
        {
            throw new HTTPException( "Failed to initialize default trust-store: %s", e, e.getMessage() );
        }

        X509TrustManager dtm = null;
        for ( final TrustManager ctm : dtmf.getTrustManagers() )
        {
            if ( ctm instanceof X509TrustManager )
            {
                dtm = (X509TrustManager) ctm;
                break;
            }
        }

        return dtm;
    }

    public static AuthScope toAuthScope( final String alias )
    {
        final Matcher m = Pattern.compile( AUTH_SCOPE_ALIAS_PATTERN )
                                 .matcher( alias );
        if ( m.matches() )
        {
            final Integer port = Integer.parseInt( m.group( 2 ) );
            return new AuthScope( m.group( 1 ), port );
        }

        return null;
    }

    public static String getAlias( final InetSocketAddress sa, final boolean client )
    {
        return ( client ? CLIENT_PREFIX : SERVER_PREFIX ) + sa.getHostName() + ":" + sa.getPort();
    }

    public static String getAlias( final AuthScope scope, final boolean client )
    {
        return ( client ? CLIENT_PREFIX : SERVER_PREFIX ) + scope.getHost() + ":" + scope.getPort();
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

    public static void readKeyAndCert( final AuthScope scope, final String pemContent, final String keyPass,
                                       final KeyStore ks )
        throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        final List<String> lines = readLines( pemContent );

        loadKeystore( ks, lines, keyPass, true, scope );
    }

    private static void loadKeystore( final KeyStore ks, final List<String> lines, final String keyPass,
                                      final boolean isClient, final AuthScope scope )
        throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException
    {
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

        final CertificateFactory certFactory = CertificateFactory.getInstance( "X.509" );
        final KeyFactory keyFactory = KeyFactory.getInstance( "RSA" );

        final List<Certificate> certs = new ArrayList<Certificate>();

        final int passes = isClient ? 2 : 1;
        for ( int pass = 0; pass < passes; pass++ )
        {
            for ( final Map.Entry<String, String> entry : entries.entrySet() )
            {
                final String header = entry.getKey();
                final byte[] data = decodeBase64( entry.getValue() );

                if ( pass > 0 && header.contains( "BEGIN PRIVATE KEY" ) )
                {
                    final KeySpec spec = new PKCS8EncodedKeySpec( data );
                    final PrivateKey key = keyFactory.generatePrivate( spec );

                    ks.setKeyEntry( getAlias( scope, isClient ), key, keyPass.toCharArray(),
                                    certs.toArray( new Certificate[] {} ) );
                }
                else if ( pass < 1 && header.contains( "BEGIN CERTIFICATE" ) )
                {
                    final Collection<? extends Certificate> c =
                        certFactory.generateCertificates( new ByteArrayInputStream( data ) );
                    int idx = 0;
                    for ( final Certificate certificate : c )
                    {
                        if ( idx == 0 )
                        {
                            final String alias = getAlias( scope, isClient );
                            ks.setCertificateEntry( alias, certificate );
                        }

                        final X509Certificate xc = (X509Certificate) certificate;
                        ks.setCertificateEntry( xc.getSubjectX500Principal()
                                                  .getName(), certificate );

                        certs.add( certificate );

                        idx++;
                    }
                }
            }
        }
    }

    public static KeyStore newKeyStore()
    {
        KeyStore ks;
        try
        {
            ks = KeyStore.getInstance( KeyStore.getDefaultType() );
            ks.load( null );
        }
        catch ( final KeyStoreException e )
        {
            throw new IllegalStateException( "Failed to create KeyStore with default algorithm." );
        }
        catch ( final NoSuchAlgorithmException e )
        {
            throw new IllegalStateException( "Failed to create KeyStore with default algorithm." );
        }
        catch ( final CertificateException e )
        {
            throw new IllegalStateException( "Failed to create KeyStore with default algorithm." );
        }
        catch ( final IOException e )
        {
            throw new IllegalStateException( "Failed to create KeyStore with default algorithm." );
        }

        return ks;
    }

    public static void readKeyAndCert( final AuthScope scope, final InputStream is, final String keyPass,
                                       final KeyStore ks )
        throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        final List<String> lines = readLines( is );
        loadKeystore( ks, lines, keyPass, true, scope );
    }

    public static void readCerts( final AuthScope scope, final String pemContent, final KeyStore ks )
        throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException
    {
        final List<String> lines = readLines( pemContent );

        try
        {
            loadKeystore( ks, lines, null, false, scope );
        }
        catch ( final InvalidKeySpecException e )
        {
            // impossible here.
        }
    }

    public static void readCerts( final AuthScope scope, final InputStream is, final KeyStore ks )
        throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException
    {
        final List<String> lines = readLines( is );

        try
        {
            loadKeystore( ks, lines, null, false, scope );
        }
        catch ( final InvalidKeySpecException e )
        {
            // impossible here.
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

    private static List<String> readLines( final String content )
        throws IOException
    {
        final List<String> lines = new ArrayList<String>();
        BufferedReader reader = null;
        try
        {
            reader =
                new BufferedReader(
                                    new InputStreamReader(
                                                           new ByteArrayInputStream(
                                                                                     content.getBytes( Charset.forName( "UTF-8" ) ) ) ) );
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
