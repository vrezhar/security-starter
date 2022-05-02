package am.ysu.security.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JWTTests
{
    @Test
    void testFaultyJWT() {
        final String authHeader = "Bearer eyJhbGciOiAiUlMyNTYiLCAidHlwIjogImp3dCIsICJraWQiOiAiMzNkZjcyY2Q3ZDkzMTQ0OTdkMTFjMTQ3MzE4MTgxZDI2ZmQ2ZTJlMjA1NDViOTJkY2Q2OWVjZGVlODAwOWZlYSJ9.eyJlbWFpbCI6ImRpbmVnbzg4ODhAcG9zaWtsYW4uY29tIiwibm9uY2UiOiJNN1hCWVpMQUJQMzRCWlg4M0FIRk5NV0JENElQTDlVOSIsImF1ZCI6Ind3dy5pZC5zdGFnaW5nLmVzdGF0ZWd1cnUuY28sIHVzZXIiLCJpc3MiOiJ3d3cuaWQuc3RhZ2luZy5lc3RhdGVndXJ1LmNvIiwiaWF0IjoxNjM3NzY2MzA0LCJleHAiOjE2Mzc3Njk5MDQsImp0aSI6IjE5ZDE2ZDg5LTA1NmEtNDM3Yi04YTRlLWZkMmEwZjk0YzI3YSIsInN1YiI6ImM5NTM4MDU2LTlhZDAtNDkzNC1hNjczLWExYWFmY2JhYjY3YyJ9.AGTHWoNzl5eLhGg423AXJTqQSW3JKORwTPZjoKqB1GXuRWbwTcNRMj_zg_7A9G4UJCHmRLHfSOohS5Cabuga5yJ745mnO3MAsClj_iKOtTMqEE72feEk_miG1EqkaCFiw1y3I7JlrPxMvsbLqVLJnm3rHU9NWYmEQpb9oUcz9k9IwUQMlSZTFIw59iEXiiB9Zf60TOQYFJYdjB2kFtxlX2VYgGKzkzNvm27fvdnxJ7RuvDVf7xHogEZNiOtM1mH00puag6O93WRYhZYimp2F5d3U4ALHwMgBDt1kl3vpkUpBjoP6fO7S1luObjZ2VDcsWjywDkDH_lNuOzJo0QQOMDQrynT8YDxC-THK005oi1oDVrGtk5IKX89V-yUNQHczOXkdNOPdN2qWJeqgJyFUwx61j0xXj0zHRo32VAO46R7sC5LDJ727Fq-wutYLS6TAF15QG-LKbhIwieptM3pI4z96gG8zGlVH595XVQzxGgWBiT0rRh3j6hnH3w5ZMHQvrjki6dvmwpuTe9O4fVQNaQlHnIJIGoWymq8ql1PG6pSXDKc_9g0x1F03wOP4rpSN0zHpQ2nprIpX4wzzSrQa2EG4i_CRk2O-ejWw6rqN0InwsodjbHn1sEeRIu3PcwkXDXlL2G6mqm3DWrUHjFe6uF_i7ditiU8tfvGrmadroMs";
        try {
            final JWT jwt = JWT.fromAuthorizationHeader(authHeader);
            assertNotNull(jwt);
            assertNotNull(jwt.getHeaderAndPayloadBytes());
            assertNotNull(jwt.getSignature());
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }
}
