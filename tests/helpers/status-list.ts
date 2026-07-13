// SPDX-License-Identifier: Apache-2.0
/**
 * Token status list helper for the U3 tests: builds a statuslist+jwt signed
 * by the test PID issuer (x5c to the test root CA, like the German profile)
 * and serves it from a local HTTP server, so revocation, outage, and
 * rate-limit paths are exercised over a real fetch.
 */

import { createPrivateKey, sign as signPayload } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { StatusList, createHeaderAndPayload } from '@owf/token-status-list';
import { PID_ISSUER_CERT_PEM, PID_ISSUER_KEY_PEM, TEST_ISSUER_URL, pemBodyBase64 } from './wallet.js';

/** Builds a statuslist+jwt with the given per-index statuses (1 bit each). */
export function buildStatusListJwt(statuses: number[]): string {
	const list = new StatusList(statuses, 1);
	const now = Math.floor(Date.now() / 1000);
	const { header, payload } = createHeaderAndPayload(
		list,
		{ iss: TEST_ISSUER_URL, sub: `${TEST_ISSUER_URL}/status/1`, iat: now, exp: now + 3600 },
		{ alg: 'ES256', typ: 'statuslist+jwt', x5c: [pemBodyBase64(PID_ISSUER_CERT_PEM)] },
	);
	const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
	const signingInput = `${encode(header)}.${encode(payload)}`;
	const signature = signPayload('sha256', Buffer.from(signingInput), {
		key: createPrivateKey(PID_ISSUER_KEY_PEM),
		dsaEncoding: 'ieee-p1363',
	});
	return `${signingInput}.${signature.toString('base64url')}`;
}

export interface StatusListServer {
	uri: string;
	close: () => Promise<void>;
}

/**
 * Serves a status list (or an HTTP error status) on 127.0.0.1. The returned
 * uri goes into the credential's `status.status_list.uri`.
 */
export async function serveStatusList(
	body: string | { httpStatus: number },
): Promise<StatusListServer> {
	const server: Server = createServer((_request, response) => {
		if (typeof body !== 'string') {
			response.writeHead(body.httpStatus, { 'Content-Type': 'text/plain' });
			response.end('error');
			return;
		}
		response.writeHead(200, { 'Content-Type': 'application/statuslist+jwt' });
		response.end(body);
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (address === null || typeof address === 'string') throw new Error('no server address');
	return {
		uri: `http://127.0.0.1:${address.port}/status/1`,
		close: () =>
			new Promise<void>((resolve, reject) => {
				server.close((err) => (err ? reject(err) : resolve()));
			}),
	};
}
