import { Test, TestingModule } from '@nestjs/testing';
import * as pactum from 'pactum';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { AppModule } from '../src/app.module';
import { LocalSignupAuthDto, LocalSigninAuthDto } from '../src/auth/dto';
import { PrismaService } from '../src/prisma/prisma.service';
import { ConfigService } from '@nestjs/config';

describe('App e2e', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let config: ConfigService;
  let serverIp: string;
  let serverPort: number;

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    config = app.get<ConfigService>(ConfigService);
    serverIp = config.get<string>('SERVER_IP');
    serverPort = config.get<number>('SERVER_PORT');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
    await app.listen(serverPort);

    prisma = app.get<PrismaService>(PrismaService);
    await prisma.cleanDb();
    pactum.request.setBaseUrl(`${serverIp}:${serverPort}/`);
  });

  afterAll(() => {
    app.close();
  });

  describe('Auth', () => {
    describe('Signup', () => {
      const dto: LocalSignupAuthDto = {
        email: 'kader@gmail.com',
        password: 'super-strong-pwd',
        firstName: 'Diarra',
        lastName: 'Kader',
      };

      describe('Signup Local', () => {
        it('Should throw error if email empty', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody({ password: 'super-strong-pwd' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if password empty', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody({ email: 'kader@gmail.com' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if no body provided', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should signup', () => {
          return pactum
            .spec()
            .post('auth/local/signup')
            .withBody(dto)
            .expectStatus(HttpStatus.CREATED)
            .expectJsonSchema('access_token', { type: 'string' });
        });
      });

      describe('Signup Google', () => {
        it('Should signin with google', () => {
          return pactum
            .spec()
            .get('auth/google')
            .withFollowRedirects(true)
            .expectStatus(HttpStatus.OK);
        });
      });
    });

    describe('Signin', () => {
      const dto: LocalSigninAuthDto = {
        email: 'kader@gmail.com',
        password: 'super-strong-pwd',
      };

      describe('Signin Local', () => {
        it('Should throw error if email empty', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody({ password: 'super-strong-pwd' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if password empty', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody({ email: 'kader@gmail.com' })
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should throw error if no body provided', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .expectStatus(HttpStatus.BAD_REQUEST);
        });

        it('Should signin', () => {
          return pactum
            .spec()
            .post('auth/local/signin')
            .withBody(dto)
            .expectStatus(HttpStatus.CREATED)
            .expectJsonSchema('access_token', { type: 'string' })
            .stores('userAccessToken', 'access_token');
        });
      });
    });

    describe('User', () => {
      describe('Get me', () => {
        it('Should get current user', () => {
          return pactum
            .spec()
            .get('users/me')
            .withHeaders({ Authorization: 'Bearer $S{userAccessToken}' })
            .expectStatus(HttpStatus.OK)
            .expectJsonSchema({
              type: 'object',
              properties: {
                id: {
                  type: 'number',
                },
                createdAt: {
                  type: 'string',
                },
                updatedAt: {
                  type: 'string',
                },
                email: {
                  type: 'string',
                },
                firstName: {
                  type: 'null',
                },
                lastName: {
                  type: 'null',
                },
                provider: {
                  type: 'string',
                },
              },
            });
        });
      });
    });
  });
});
