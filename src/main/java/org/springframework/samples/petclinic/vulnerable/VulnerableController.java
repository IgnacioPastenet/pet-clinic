package org.springframework.samples.petclinic.vulnerable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * ARCHIVO VULNERABLE INTENCIONAL - Solo para evidenciar controles SAST
 * Este archivo contiene vulnerabilidades de seguridad a proposito
 * para demostrar que el pipeline DevSecOps detecta y bloquea codigo inseguro.
 */
@RestController
public class VulnerableController {

	// VULNERABILIDAD 1: SQL Injection (CWE-89) - CRITICAL/HIGH
	@GetMapping("/vulnerable/search")
	public String searchUser(@RequestParam String username) throws Exception {
		Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
		Statement stmt = conn.createStatement();
		// Concatenacion directa de input del usuario en consulta SQL
		String query = "SELECT * FROM users WHERE username = '" + username + "'";
		ResultSet rs = stmt.executeQuery(query);
		return rs.toString();
	}

	// VULNERABILIDAD 2: Cross-Site Scripting XSS (CWE-79) - HIGH/MEDIUM
	@GetMapping("/vulnerable/greet")
	public String greetUser(@RequestParam String name) {
		// Retorna input del usuario sin sanitizar directamente en HTML
		return "<html><body><h1>Hola " + name + "</h1></body></html>";
	}

	// VULNERABILIDAD 3: Path Traversal (CWE-22) - HIGH
	@GetMapping("/vulnerable/file")
	public String readFile(@RequestParam String filename) throws Exception {
		// Lee archivo usando input del usuario sin validacion
		java.io.File file = new java.io.File("/data/" + filename);
		return new String(java.nio.file.Files.readAllBytes(file.toPath()));
	}

	// VULNERABILIDAD 4: Command Injection (CWE-78) - CRITICAL
	@GetMapping("/vulnerable/exec")
	public String executeCommand(@RequestParam String cmd) throws Exception {
		// Ejecuta comando del sistema operativo con input del usuario
		Process process = Runtime.getRuntime().exec(cmd);
		java.io.InputStream is = process.getInputStream();
		return new String(is.readAllBytes());
	}

}
