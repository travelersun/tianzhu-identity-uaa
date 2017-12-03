/**
 * 
 */
package com.tianzhu.identity.uaa.db;

import com.tianzhu.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author nmalp
 *
 */
public class TestDataSourcePool extends JdbcTestBase {

	@Test
	public void testValidationQuery() {
		int i = jdbcTemplate.queryForObject(this.validationQuery, Integer.class);
		assertEquals(1, i);
	}

}
