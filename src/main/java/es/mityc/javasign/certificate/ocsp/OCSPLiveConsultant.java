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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */

package es.mityc.javasign.certificate.ocsp;

//import java.net.Authenticator;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import es.mityc.firmaJava.ocsp.OCSPCliente;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.firmaJava.ocsp.exception.OCSPClienteException;
import es.mityc.firmaJava.ocsp.exception.OCSPProxyException;
import es.mityc.javasign.certificate.CertStatusException;
import es.mityc.javasign.certificate.ICertStatus;
import es.mityc.javasign.certificate.ICertStatusRecoverer;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.trust.UnknownTrustException;

/**
 * <p>
 * Recupera el estado de un certificado mediante una consulta OCSP a un OCSP responder disponible por canal HTTP.
 * </p>
 * 
 * @author Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
@SuppressWarnings("deprecation")
public class OCSPLiveConsultant implements ICertStatusRecoverer {

	/** Internacionalizador. */
	// private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsOCSP.LIB_NAME);

	// private boolean hasProxy;
	// private boolean isProxyAuth;
	// private String servidorProxy;
	// private int numeroPuertoProxy;
	// private String proxyUser;
	// private transient String proxyPass;
	/** Ruta del servidor HTTP OCSP al que se realiza la consulta. */
	private String servidorOCSP;
	/** Validador de confianza */
	private TrustAbstract validadorConfianza;

	/**
	 * <p>
	 * Constructor.
	 * </p>
	 * 
	 * @param hostOCSPResponder
	 *            url del servidor OCSP responder al que envían las consultas
	 * @param truster
	 *            Validador de confianza
	 */
	public OCSPLiveConsultant(String hostOCSPResponder, TrustAbstract truster) {
		servidorOCSP = hostOCSPResponder;
		validadorConfianza = truster;
	}

	// public void setProxy(String host, int port, String proxyUser, String proxyPass) {
	// hasProxy = true;
	// servidorProxy = host;
	// numeroPuertoProxy = port;
	// if (proxyUser != null)
	// isProxyAuth = true;
	// this.proxyUser = proxyUser;
	// this.proxyPass = proxyPass;
	// }

	/**
	 * <p>
	 * No implementado.
	 * </p>
	 * 
	 * @param certList
	 *            no implementado
	 * @return no implementado
	 * @throws CertStatusException
	 *             no implementado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertStatus(java.util.List)
	 */
	public List<ICertStatus> getCertStatus(final List<X509Certificate> certList) throws CertStatusException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Not implemented yet");
	}

	/**
	 * <p>
	 * Realiza una consulta de estado de un certificado sobre el OCSP Responder configurado.
	 * </p>
	 * 
	 * @param cert
	 *            Certificado a consultar
	 * @return Estado del certificado indicado
	 * @throws CertStatusException
	 *             Lanzada si sucede algún problema durante la consulta de estado del certificado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertStatus(java.security.cert.X509Certificate)
	 */
	public ICertStatus getCertStatus(final X509Certificate cert) throws CertStatusException {
		
		// Obtenemos la respuesta del servidor OCSP
		// String tiempoRespuesta = ConstantesXADES.CADENA_VACIA;
		OCSPCliente ocspCliente = null;
		OCSPStatus bloque = null;
		RespuestaOCSP respuesta = null;
		// byte[] respuestaOCSP = null;
		try {
			// if(hasProxy)
			// {
			// System.setProperty("http.proxyHost", servidorProxy);
			// System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
			// if (isProxyAuth) {
			// Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
			// }
			// else {
			// Authenticator.setDefault(null);
			// }
			// }
			ocspCliente = new OCSPCliente(servidorOCSP);

			// Construimos la cadena de certificacion del certificado
			CertPath certPath = validadorConfianza.getCertPath(cert);
			List<? extends Certificate> certificates = certPath.getCertificates();
			X509Certificate issuerCertificate;
			if (certificates.size() > 1) {
				issuerCertificate = (X509Certificate) certificates.get(1);
			} else {
				issuerCertificate = (X509Certificate) certificates.get(0);
			}

			respuesta = ocspCliente.validateCert(cert, issuerCertificate);
			// tiempoRespuesta = UtilidadFechas.formatFechaXML(respuesta.getTiempoRespuesta());
		} catch (OCSPClienteException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		} catch (OCSPProxyException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		} catch (UnknownTrustException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		}

		// // Solo continúa si el certificado es válido
		// if (respuesta.getNroRespuesta() != 0) {
		// throw new ClienteError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_9));
		// }

		// respuestaOCSP = respuesta.getRespuesta();

		bloque = new OCSPStatus(respuesta, cert);
		// bloque.setX509Cert(cert);
		// RespOCSP ocspBloque = new RespOCSP(respuesta);
		// ocspBloque.setRespOCSP(respuestaOCSP);
		// ocspBloque.setTiempoRespuesta(tiempoRespuesta);
		// ocspBloque.setResponder(respuesta.getValorResponder(), respuesta.getTipoResponder());
		// bloque.setCertstatus(ocspBloque);

		return bloque;
	}

	/**
	 * <p>
	 * Recupera el estado de la cadena de certificación del certificado indicado.
	 * </p>
	 * 
	 * @param cert
	 *            Certificado que se consulta
	 * @return Lista de estados de la cadena de certificación del certificado consultado. El primer elemento de la lista será el estado del
	 *         propio certificado.
	 * @throws CertStatusException
	 *             Lanzada cuando no se puede recuperar el estado del certificado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertChainStatus(java.util.List)
	 */
	public List<ICertStatus> getCertChainStatus(X509Certificate cert) throws CertStatusException {
		// Obtenemos la respuesta del servidor OCSP
		OCSPCliente ocspCliente = null;
		List<ICertStatus> result = new ArrayList<ICertStatus>();
		try {
			ocspCliente = new OCSPCliente(servidorOCSP);

			// Construimos la cadena de certificacion del certificado
			CertPath certPath = validadorConfianza.getCertPath(cert);
			List<? extends Certificate> certificates = certPath.getCertificates();
			int certificatesSize = certificates.size();
			for (int i = 0; i < certificatesSize; i++) {
				X509Certificate certificateToValidate = (X509Certificate) certificates.get(i);
				X509Certificate issuerCertificate;
				// Si es el ultimo certificado estamos ante el certificado raiz en el que el emisor es él mismo
				if (i == certificatesSize - 1) {
					issuerCertificate = (X509Certificate) certificates.get(i);
				} else {
					issuerCertificate = (X509Certificate) certificates.get(i + 1);
				}
				RespuestaOCSP respuesta = ocspCliente.validateCert(certificateToValidate, issuerCertificate);
				OCSPStatus bloque = new OCSPStatus(respuesta, certificateToValidate);
				result.add(bloque);
			}

		} catch (OCSPClienteException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		} catch (OCSPProxyException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		} catch (UnknownTrustException ex) {
			throw new CertStatusException(ex.getMessage(), ex);
		}

		return result;
	}

	/**
	 * <p>
	 * Operación no soportada.
	 * </p>
	 * 
	 * @param cert
	 *            no utilizado
	 * @return no utilizado
	 * @throws CertStatusException
	 *             no utilizado
	 * @see es.mityc.javasign.certificate.ICertStatusRecoverer#getCertChainStatus(java.security.cert.X509Certificate)
	 */
	public List<List<ICertStatus>> getCertChainStatus(List<X509Certificate> certs) throws CertStatusException {
		throw new UnsupportedOperationException("Not Supported Operation");
	}

}
