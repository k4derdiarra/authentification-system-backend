import { ForbiddenException, Injectable } from '@nestjs/common';
import { LocalSignupAuthDto, GoogleAuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LocalSigninAuthDto } from './dto';
import { JwtPayloadDto } from './dto';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signupLocal(dto: LocalSignupAuthDto): Promise<Tokens> {
    try {
      // TODO: generate the password hash
      const hash = await this.hashData(dto.password);

      // TODO: save user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          firstName: dto.firstName,
          lastName: dto.lastName,
          hash,
        },
      });

      // TODO: create access and refresh tokens
      const tokens = await this.getTokens({
        sub: user.id,
        email: user.email,
      });
      // TODO: update old refresh token
      await this.updateRefreshTokenInDatabase(tokens.refresh_token, user.id);

      // TODO: return jwt token
      return tokens;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signinLocal(dto: LocalSigninAuthDto) {
    // TODO: retrieve user from db
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // TODO: if user does not exist throw error
    if (!user) throw new ForbiddenException('Credentials incorrect');

    // TODO: compare password to hash
    const pwdMatches = await bcrypt.compare(dto.password, user.hash);
    // TODO: if password incorrect throw error
    if (!pwdMatches) throw new ForbiddenException('Credentials incorrect');

    // TODO: create access and refresh tokens
    const tokens = await this.getTokens({
      sub: user.id,
      email: user.email,
    });
    // TODO: update old refresh token
    await this.updateRefreshTokenInDatabase(tokens.refresh_token, user.id);

    // TODO: return jwt token
    return tokens;
  }

  async signinGoogle(dto: GoogleAuthDto): Promise<Tokens> {
    try {
      // TODO: get user from db
      let user = await this.prisma.user.findFirst({
        where: { email: dto.email, provider: 'google' }, // if provider not google reject
      });
      // TODO: create user in db if not exist
      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: dto.email,
            firstName: dto.firstName,
            lastName: dto.lastName,
            provider: dto.provider,
            googleAccessToken: dto.accessToken,
            googleRefreshToken: dto.refreshToken,
          },
        });
      }

      // TODO: create access and refresh tokens
      const tokens = await this.getTokens({
        sub: user.id,
        email: user.email,
      });
      // TODO: update old refresh token
      await this.updateRefreshTokenInDatabase(tokens.refresh_token, user.id);

      // TODO: return jwt token
      return tokens;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async hashData(data: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(data, salt);
  }

  // TODO: create access token
  async getAccessToken(payload: JwtPayloadDto): Promise<string> {
    const accessToken = await this.jwt.signAsync(payload, {
      secret: this.config.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
    });

    return accessToken;
  }

  // TODO: create refresh token and store it (hashed)
  async getRefreshToken(payload: JwtPayloadDto): Promise<string> {
    const refreshToken = await this.jwt.signAsync(payload, {
      secret: this.config.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
    });

    return refreshToken;
  }

  // TODO: create access and refresh token
  async updateRefreshTokenInDatabase(
    refreshToken: string | null,
    userId: number,
  ): Promise<void> {
    // TODO: if not null hash refresh token
    const hashedRefreshToken = refreshToken
      ? await this.hashData(refreshToken)
      : null;

    // TODO: update refresh token in db
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRefreshToken },
    });
  }

  // TODO: return access and refresh token
  async getTokens(payload: JwtPayloadDto): Promise<Tokens> {
    // TODO: create tokens
    const [accessToken, refreshToken] = await Promise.all([
      this.getAccessToken(payload),
      this.getRefreshToken(payload),
    ]);

    // TODO: return tokens
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  // TODO: delete refresh token from db
  // TODO: if refresh token stolen, delete RF of victim

  async logout(userId: number): Promise<boolean> {
    // TODO: remove refresh token from DB
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: {
          not: null,
        },
      },
      data: {
        hashedRefreshToken: null,
      },
    });
    return true;
  }

  async refreshTokens(userId: number, refreshToken: string): Promise<Tokens> {
    // TODO: get user from db
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    // TODO: if user not exist throw error
    if (!user || !user.hashedRefreshToken)
      throw new ForbiddenException('Access Denied');
    // TODO: check if refresh tokens match
    const isRefreshTokensMatches = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    );
    // TODO: if tokens not match throw error
    if (!isRefreshTokensMatches) throw new ForbiddenException('Access Denied');
    // TODO: if tokens match generate new tokens
    const tokens = await this.getTokens({ sub: user.id, email: user.email });
    // TODO: update refresh token in db
    await this.updateRefreshTokenInDatabase(tokens.refresh_token, user.id);
    // TODO: return new token
    return tokens;
  }
}
