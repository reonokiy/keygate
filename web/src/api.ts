export interface Identity {
  subject: string;
  user_id: string;
}

export interface ApiKey {
  id: string;
  name: string;
  created_at: number;
  revoked: boolean;
}

export interface Application {
  id: string;
  name: string;
  keys: ApiKey[];
}

export interface IssuedKey {
  id: string;
  key: string;
}

interface KeyName {
  name: string;
}

type Method = 'GET' | 'POST' | 'DELETE';

async function request(path: string, method: Method = 'GET', body?: KeyName): Promise<Response> {
  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      'X-Keygate-CSRF': '1',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const data: unknown = await response.json().catch(() => null);
    const message = typeof data === 'object' && data !== null && 'error' in data
      && typeof data.error === 'string' && data.error
      ? data.error
      : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return response;
}

async function json<T>(path: string, method: Method = 'GET', body?: KeyName): Promise<T> {
  const response = await request(path, method, body);
  return response.json() as Promise<T>;
}

export function getIdentity(): Promise<Identity> {
  return json<Identity>('api/me');
}

export function getApplications(): Promise<Application[]> {
  return json<Application[]>('api/apps');
}

export function issueKey(appId: string, name: string): Promise<IssuedKey> {
  return json<IssuedKey>(`api/apps/${encodeURIComponent(appId)}/keys`, 'POST', { name });
}

export async function revokeKey(appId: string, keyId: string): Promise<void> {
  await request(`api/apps/${encodeURIComponent(appId)}/keys/${encodeURIComponent(keyId)}`, 'DELETE');
}
