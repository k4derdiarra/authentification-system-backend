import { AuthGuard } from '@nestjs/passport';

export class JwtRefreshTokenGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
