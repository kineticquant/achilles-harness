export type HttpRole = 'client' | 'server';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'ANY';

export type HttpHit = {
  method: HttpMethod;
  path: string;
  file: string;
  line: number;
  fn: string;
  role: HttpRole;
  helper?: string;
};
