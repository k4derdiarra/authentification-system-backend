import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { User } from '@prisma/client';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtPayload } from '../types';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  async validate(payload: JwtPayload): Promise<User> {
    // TODO: get user from db
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    // ! Not recommended, Find another method
    if (user)
      this.prisma.deleteField<User>(
        [
          'hash',
          'googleRefreshToken',
          'hashedRefreshToken',
          'googleAccessToken',
        ],
        user,
      );
    else throw new UnauthorizedException('User not found');

    // TODO: return user
    return user;
  }
}
