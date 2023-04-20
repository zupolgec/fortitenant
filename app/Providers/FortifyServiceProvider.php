<?php

namespace App\Providers;

use App\Actions\Fortify\CreateNewUser;
use App\Actions\Fortify\ResetUserPassword;
use App\Actions\Fortify\UpdateUserPassword;
use App\Actions\Fortify\UpdateUserProfileInformation;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Fortify\Fortify;
use Stancl\Tenancy\Exceptions\TenantCouldNotBeIdentifiedOnDomainException;
use Stancl\Tenancy\Resolvers\DomainTenantResolver;
use Stancl\Tenancy\Tenancy;

class FortifyServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(StatefulGuard::class, function () {
            /** @var Request $request */
            $request = app('request');

            $tenantDomain = $request->getHost();

            if (!in_array($tenantDomain, config('tenancy.central_domains'), true)) {
                /** @var Tenancy $tenancy */
                $tenancy = app(Tenancy::class);
                /** @var DomainTenantResolver $tenantResolver */
                $tenantResolver = app(DomainTenantResolver::class);

                try {
                    if (!$tenancy->initialized) {
                        $tenancy->initialize(
                            $tenantResolver->resolve(
                                $tenantDomain
                            )
                        );
                    }
                } catch (TenantCouldNotBeIdentifiedOnDomainException $e) {
                    return Auth::guard(config('fortify.guard', null));
                }
            }

            return Auth::guard(config('fortify.guard', null));
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Fortify::createUsersUsing(CreateNewUser::class);
        Fortify::updateUserProfileInformationUsing(UpdateUserProfileInformation::class);
        Fortify::updateUserPasswordsUsing(UpdateUserPassword::class);
        Fortify::resetUserPasswordsUsing(ResetUserPassword::class);

        RateLimiter::for('login', function (Request $request) {
            $email = (string) $request->email;

            return Limit::perMinute(5)->by($email.$request->ip());
        });

        RateLimiter::for('two-factor', function (Request $request) {
            return Limit::perMinute(5)->by($request->session()->get('login.id'));
        });
    }
}
