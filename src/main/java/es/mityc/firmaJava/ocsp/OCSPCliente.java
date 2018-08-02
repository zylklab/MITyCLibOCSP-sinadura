/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2008 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ocsp;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;



import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import es.mityc.firmaJava.ocsp.config.ConfigProveedores;
import es.mityc.firmaJava.ocsp.config.ServidorOcsp;
import es.mityc.firmaJava.ocsp.exception.OCSPClienteException;
import es.mityc.firmaJava.ocsp.exception.OCSPProxyException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 * @deprecated Usar la clase OCSPLiveConsultant en su lugar
 */
public class OCSPCliente {

//    private static final Integer INT_5000 = new Integer(5000);
	
	private String 	servidorURL;

    static Log log = LogFactory.getLog(OCSPCliente.class);


    /**
     * Constructor de la clase OCSPCliente
     * @param servidorURL Servidor URL
     */
    public OCSPCliente(String servidorURL)
    {
        this.servidorURL = servidorURL;
    }


    /**
     * Este método valida el Certificado contra un servidor OCSP
     * @param certificadoUsuario Certificado
     * @param certificadoEmisor Certificado del emisor. En el caso de un certificado autofirmado el certificado del emisor será el mismo que el del usuario
     * @return respuestaOCSP tipo número de respuesta y mensaje correspondiente
     * @throws OCSPClienteException Errores del cliente OCSP
     */
	public RespuestaOCSP validateCert(X509Certificate certificadoUsuario, X509Certificate certificadoEmisor) throws OCSPClienteException,
			OCSPProxyException {
	
		log.info("ocsp validator init");

		RespuestaOCSP respuesta = new RespuestaOCSP();

		// Añadimos el proveedor BouncyCastle
		Security.addProvider(new BouncyCastleProvider());
		OCSPReqGenerator generadorPeticion = new OCSPReqGenerator();
		OCSPReq peticionOCSP = null;
		OCSPResp respuestaOCSP = null;
		CertificateID certificadoId = null;

		try {
			certificadoId = new CertificateID(CertificateID.HASH_SHA1, certificadoEmisor, certificadoUsuario.getSerialNumber());
			log.info(ConstantesOCSP.MENSAJE_CREADO_INDENTIFICADO);
			
		} catch (OCSPException e) {
			log.info(ConstantesOCSP.MENSAJE_ERROR_GENERAR_IDENTIFICADOR + e.getMessage(), e);
			throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_2) + ConstantesOCSP.DOS_PUNTOS_ESPACIO
					+ e.getMessage());
		}

		generadorPeticion.addRequest(certificadoId);

		try {
			peticionOCSP = generadorPeticion.generate();
			log.info(ConstantesOCSP.MENSAJE_PETICION_OCSP_GENERADA);

		} catch (OCSPException e) {
			log.error(ConstantesOCSP.ERROR_MENSAJE_GENERAR_PETICION_OCSP + e.getMessage(), e);
			throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_3) + ConstantesOCSP.DOS_PUNTOS_ESPACIO
					+ e.getMessage());
		}

        // httpclient
//        HttpClient cliente = new HttpClient();
//        
//        cliente.getParams().setParameter(HttpClientParams.SO_TIMEOUT, INT_5000);
//
//
//        // Comprueba si hay configurado un proxy 
//        String servidorProxy = System.getProperty("http.proxyHost");
//        if (servidorProxy != null)
//        {
//        	int puertoProxy = 80;
//        	try {
//        		puertoProxy = Integer.parseInt(System.getProperty("http.proxyPort"));
//        	} catch (NumberFormatException ex) {
//        	}
//        	cliente.getHostConfiguration().setProxy(servidorProxy, puertoProxy);
//        	
//    		Credentials defaultcreds = new AuthenticatorProxyCredentials(servidorProxy, ConstantesOCSP.CADENA_VACIA);
//    		cliente.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
//        }
//        
//        
//        if (((servidorURL == null) || ("".equals(servidorURL.trim())))
//        		|| 
//        		servidorURL.trim().equalsIgnoreCase(ConstantesOCSP.USAR_OCSP_MULTIPLE)
//        ) {
//
//        	ServidorOcsp servidor = ConfigProveedores.getServidor(certificadoUsuario);
//
//        	if (null != servidor) {
//
//        		servidorURL = servidor.getUrl().toString();
//        		log.debug(ConstantesOCSP.DEBUG_SERVIDOR_OCSP_ENCONTRADO + servidorURL);
//        	} else {
//        		log.error(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
//        		servidorURL = ConstantesOCSP.CADENA_VACIA;
//        		throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
//
//        	}
//
//        }
//
//
//        PostMethod metodo = new PostMethod(servidorURL);
//        
//        metodo.addRequestHeader(ConstantesOCSP.CONTENT_TYPE, ConstantesOCSP.APPLICATION_OCSP_REQUEST);
//        ByteArrayInputStream datos = null;
//
//        try
//        {
//            datos = new ByteArrayInputStream(peticionOCSP.getEncoded());
//
//        }
//        catch (IOException e)
//        {
//        	
//        	log.error( ConstantesOCSP.MENSAJE_ERROR_LEER_PETICION + e.getMessage());
//            throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_4) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
//        }
//
//        InputStreamRequestEntity rq = new InputStreamRequestEntity (datos);
//        metodo.setRequestEntity(rq);
//        
//        metodo.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
//                new DefaultHttpMethodRetryHandler(3, false));
//
//        try
//        {
//        	int estadoCodigo = cliente.executeMethod(metodo);
//            log.info(ConstantesOCSP.MENSAJE_PETICION_ENVIADA);           
//
//            if (estadoCodigo != HttpStatus.SC_OK)
//            {
//            	if (estadoCodigo == HttpStatus.SC_PROXY_AUTHENTICATION_REQUIRED)
//                	throw new OCSPProxyException(ConstantesOCSP.MENSAJE_PROXY_AUTENTICADO);
//                else if (estadoCodigo == HttpStatus.SC_USE_PROXY)
//                	throw new OCSPProxyException(ConstantesOCSP.MENSAJE_PROXY_POR_CONFIGURAR);
//                else {
//                	log.error( ConstantesOCSP.MENSAJE_FALLO_EJECUCION_METODO + metodo.getStatusLine());
//                	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_9) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + metodo.getStatusLine());
//                }
//            }
//
//            byte[] cuerpoRespuesta = metodo.getResponseBody();
//            log.info(ConstantesOCSP.MENSAJE_RESPUESTA_OBTENIDA);
//            
//
//            try
//            {
//            	respuestaOCSP = new OCSPResp(cuerpoRespuesta);
//            }
//            catch (IOException e)
//            {
//            	log.error( ConstantesOCSP.MENSAJE_ERROR_SECUENCIA_BYTES_RESPUESTA + e.getMessage());
//                throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_5) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
//            }
//
//            /*
//              Estados de la respuesta OCSP
//                successful            (0) La respuesta tiene una confirmación válida
//                malformedRequest      (1) La petición no se realizó de forma correcta
//                internalError         (2) Error interno
//                tryLater              (3) Vuelva a intentarlo
//                                       -  (4) no se utiliza
//                sigRequired           (5) La petición debe estar firmada
//                unauthorized          (6) No se ha podido autorizar la petición
//
//            */
//            
//            processResponse(respuestaOCSP, respuesta, certificadoId);
//
//        }
//        catch (HttpException e)
//        {
//        	log.error( ConstantesOCSP.MENSAJE_VIOLACION_HTTP + e.getMessage());
//        	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_7) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
//        }
//        catch (IOException e)
//        {
//        	String mensajeError = I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_10) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + servidorURL;
//        	log.error( ConstantesOCSP.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage());
//        	throw new OCSPClienteException(mensajeError);
//        }
//        finally
//        {
//            Security.removeProvider(ConstantesOCSP.BC);
//            metodo.releaseConnection();
//        }
        
        
        
        // java
		if (((servidorURL == null) || ("".equals(servidorURL.trim())))
				|| servidorURL.trim().equalsIgnoreCase(ConstantesOCSP.USAR_OCSP_MULTIPLE)) {

			ServidorOcsp servidor = ConfigProveedores.getServidor(certificadoUsuario);

			if (null != servidor) {
				servidorURL = servidor.getUrl().toString();
				log.debug(ConstantesOCSP.DEBUG_SERVIDOR_OCSP_ENCONTRADO + servidorURL);
			} else {
				log.error(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
				servidorURL = ConstantesOCSP.CADENA_VACIA;
				throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_12));
			}
		}
		
		try {
			URL urlt = new URL(servidorURL);
			HttpURLConnection con = (HttpURLConnection) urlt.openConnection();
			con.setConnectTimeout(5000);
			con.setRequestProperty(ConstantesOCSP.CONTENT_TYPE, ConstantesOCSP.APPLICATION_OCSP_REQUEST);
			con.setRequestProperty("Accept", "application/ocsp-response");
			con.setDoOutput(true);
			OutputStream out = con.getOutputStream();
			DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
			dataOut.write(peticionOCSP.getEncoded());
			dataOut.flush();
			dataOut.close();
			
			log.info(ConstantesOCSP.MENSAJE_RESPUESTA_OBTENIDA);
			
			log.info("http code: " + con.getResponseCode());
			
			if (con.getResponseCode() / 100 != 2) {
				log.error(ConstantesOCSP.MENSAJE_FALLO_EJECUCION_METODO + con.getResponseCode());
				throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_9) + ConstantesOCSP.DOS_PUNTOS_ESPACIO
						+ con.getResponseCode());
			}
			
			// Get Response
			InputStream in = (InputStream) con.getContent();
			
			try {
				respuestaOCSP = new OCSPResp(in);
				
			} catch (IOException e) {
				log.error(ConstantesOCSP.MENSAJE_ERROR_SECUENCIA_BYTES_RESPUESTA + e.getMessage(), e);
				throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_5) + ConstantesOCSP.DOS_PUNTOS_ESPACIO
						+ e.getMessage());
			}
	
			/*
			* Estados de la respuesta OCSP successful (0) La respuesta tiene una confirmación válida malformedRequest (1) La petición no se
			* realizó de forma correcta internalError (2) Error interno tryLater (3) Vuelva a intentarlo - (4) no se utiliza sigRequired
			* (5) La petición debe estar firmada unauthorized (6) No se ha podido autorizar la petición
			*/
	
			processResponse(respuestaOCSP, respuesta, certificadoId);
		
		} catch (IOException e) {
			
			log.error(ConstantesOCSP.MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage(), e);
	      	String mensajeError = I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_10) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + servidorURL;
	      	throw new OCSPClienteException(mensajeError);
	      	
		}  finally {
			Security.removeProvider(ConstantesOCSP.BC);
		}
		
        log.info("ocsp validator end");
        
        return respuesta;
    }
    
    public static void processResponse(OCSPResp inResp, RespuestaOCSP outResp, CertificateID certID) throws OCSPClienteException, IOException {
    	
    	outResp.setRespuesta(inResp);
        if (inResp.getStatus() != 0)
        {
        	log.info(ConstantesOCSP.MENSAJE_OCSP_NOT_SUCCESSFUL);
        	switch (inResp.getStatus())
        	{
	            case 1:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_MALFORMED_REQUEST);
	            			outResp.setNroRespuesta(ConstantesOCSP.MALFORMEDREQUEST);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_1));
	            			
	            			break;
	            case 2:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_INTERNAL_ERROR);
	            			outResp.setNroRespuesta(ConstantesOCSP.INTERNALERROR);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_2));
	            			break;
	            case 3:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_TRY_LATER);
	            			outResp.setNroRespuesta(ConstantesOCSP.TRYLATER);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_3));
	            			break;
	            case 5:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_SIG_REQUIRED);
	            			outResp.setNroRespuesta(ConstantesOCSP.SIGREQUIRED);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_4));
	            			break;
	            case 6:
	            			log.warn(ConstantesOCSP.MENSAJE_OCSP_UNAUTHORIZED);
	            			outResp.setNroRespuesta(ConstantesOCSP.UNAUTHORIZED);
	            			outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_RESPUESTA_5));
	            			break;
        	}
        }
        else
        {
            try
            {
            	log.info(ConstantesOCSP.MENSAJE_OCSP_SUCCESSFUL);
                BasicOCSPResp respuestaBasica = (BasicOCSPResp)inResp.getResponseObject();
				
                try {
                	X509Certificate certs[] = respuestaBasica.getCerts(ConstantesOCSP.SUN);
                	if ((certs != null) && (certs.length > 0)) {
                		ArrayList<X509Certificate> list = new ArrayList<X509Certificate>(certs.length);
                		for (int i = 0; i < certs.length; i++)
                			list.add(certs[i]);
                		outResp.setOCSPSigner(list);
                	}
				} catch (NoSuchProviderException e) {
					log.info(e.getMessage(), e);
				} catch (OCSPException e) {
					log.info(e.getMessage(), e);
				}
                
                SingleResp[] arrayRespuestaBasica = respuestaBasica.getResponses();
                outResp.setTiempoRespuesta(respuestaBasica.getProducedAt());
                ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
                outResp.setResponder(respID);
                StringBuffer mensaje = new StringBuffer(ConstantesOCSP.MENSAJE_RECIBIDO_ESTADO_NO_DEFINIDO);

                boolean finded = false;
                for (int i = 0; i<arrayRespuestaBasica.length;i++)
                {
                	// Comprueba si es la respuesta esperada
                	SingleResp sr = arrayRespuestaBasica[i];
                	if (!certID.equals(sr.getCertID()))
            			continue;
                	
                	finded = true;
                	Object certStatus = arrayRespuestaBasica[i].getCertStatus();
                	if (certStatus == null)
                    {
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_GOOD);
                    	outResp.setNroRespuesta(ConstantesOCSP.GOOD);
                    	outResp.setMensajeRespuesta(new String(Base64Coder.encode(inResp.getEncoded())));
                    }
                	else if (certStatus instanceof RevokedStatus)
                    {
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_REVOKED);
                    	outResp.setFechaRevocacion(((RevokedStatus)certStatus).getRevocationTime());
                    	outResp.setNroRespuesta(ConstantesOCSP.REVOKED);

                        /*
                        Razones de revocación
                        	unused 					(0) Sin uso
                        	keyCompromise 			(1) Se sospecha que la clave del certificado ha quedado comprometida
                        	cACompromise			(2) Se sospecha que la clave que firmó el certificado ha quedado comprometida
                        	affiliationChanged		(3) Se han cambiado los datos particulares del certificado
                        	superseded	      		(4) El certificado ha sido reemplazado por otro
                        	cessationOfOperation	(5) El certificado ha dejado de operar
                        	certificateHold 		(6) El certificado momentáneamente ha dejado de operar
						*/

                        RevokedStatus revoked = (RevokedStatus)certStatus;
                        if (revoked.hasRevocationReason())
                        {
	                        switch (revoked.getRevocationReason())
	                        {
	                        
	                        	case 1:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_1));
                        			break;
	                        	case 2:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_2));
                    				break;
	                        	case 3:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_3));
                    				break;
	                        	case 4:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_4));
                    				break;
	                        	case 5:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_5));
                    				break;
	                        	case 6:
	                        		outResp.setMensajeRespuesta(I18n.getResource(ConstantesOCSP.LIBRERIA_RAZON_REVOCACION_6));
                    				break;
	                        	default:
	                        		outResp.setMensajeRespuesta(ConstantesOCSP.CADENA_VACIA);
	                        }
                        }
                        else
                        	outResp.setMensajeRespuesta(ConstantesOCSP.CADENA_VACIA);
                    }
                    else if (certStatus instanceof UnknownStatus)
                    {
                    	
                    	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_UNKNOWN);
                    	outResp.setNroRespuesta(ConstantesOCSP.UNKNOWN) ;
                    	// aqui (I18n.getResource
                    	outResp.setMensajeRespuesta(ConstantesOCSP.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                    }
                    else
                    {
                    	mensaje.append(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    	log.info( mensaje.toString());
                    	outResp.setNroRespuesta(ConstantesOCSP.ERROR) ;
                    	outResp.setMensajeRespuesta(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
                    }
                }
                
                if (!finded) {
                	log.info(ConstantesOCSP.ESTADO_CERTIFICADO_UNKNOWN);
                	outResp.setNroRespuesta(ConstantesOCSP.UNKNOWN) ;
                	// aqui (I18n.getResource
                	outResp.setMensajeRespuesta(ConstantesOCSP.MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
                }
            }
            catch (OCSPException e)
            {
            	log.error( ConstantesOCSP.MENSAJE_ERROR_RESPUESTA_OCPS_BASICA + e.getMessage());
            	throw new OCSPClienteException(I18n.getResource(ConstantesOCSP.LIBRERIA_OCSP_ERROR_6) + ConstantesOCSP.DOS_PUNTOS_ESPACIO + e.getMessage());
            }
        }
    }
}
