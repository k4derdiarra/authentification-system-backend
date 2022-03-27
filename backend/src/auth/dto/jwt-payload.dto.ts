export interface JwtPayloadDto {
  sub: number;
  email: string;
}

export type JwtAccessAndRefreshTokenDto = Promise<{
  accessToken: string;
  refreshToken: string;
}>;
