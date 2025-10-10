import React, { forwardRef } from 'react';
import clsx from 'clsx';
import './Input.css';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
  icon?: React.ReactNode;
  iconPosition?: 'left' | 'right';
  fullWidth?: boolean;
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, icon, iconPosition = 'left', fullWidth = false, className, ...props }, ref) => {
    return (
      <div className={clsx('input-wrapper', { 'input-full': fullWidth })}>
        {label && <label className="input-label">{label}</label>}
        <div className={clsx('input-container', { 'input-error': error })}>
          {icon && iconPosition === 'left' && <span className="input-icon input-icon-left">{icon}</span>}
          <input
            ref={ref}
            className={clsx(
              'input',
              {
                'input-with-icon-left': icon && iconPosition === 'left',
                'input-with-icon-right': icon && iconPosition === 'right',
              },
              className
            )}
            {...props}
          />
          {icon && iconPosition === 'right' && <span className="input-icon input-icon-right">{icon}</span>}
        </div>
        {error && <span className="input-message input-message-error">{error}</span>}
        {hint && !error && <span className="input-message input-message-hint">{hint}</span>}
      </div>
    );
  }
);

Input.displayName = 'Input';

export default Input;
