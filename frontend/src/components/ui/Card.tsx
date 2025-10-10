import React from 'react';
import clsx from 'clsx';
import './Card.css';

interface CardProps {
  children: React.ReactNode;
  title?: string;
  description?: string;
  actions?: React.ReactNode;
  className?: string;
  variant?: 'default' | 'elevated' | 'bordered';
  padding?: 'none' | 'sm' | 'md' | 'lg';
  onClick?: () => void;
}

export default function Card({
  children,
  title,
  description,
  actions,
  className,
  variant = 'default',
  padding = 'md',
  onClick,
}: CardProps) {
  return (
    <div
      className={clsx(
        'card',
        `card-${variant}`,
        `card-padding-${padding}`,
        {
          'card-clickable': onClick,
        },
        className
      )}
      onClick={onClick}
    >
      {(title || description || actions) && (
        <div className="card-header">
          <div className="card-header-content">
            {title && <h3 className="card-title">{title}</h3>}
            {description && <p className="card-description">{description}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      <div className="card-body">{children}</div>
    </div>
  );
}
